#!/usr/bin/env python3
# Copyright (c) 2014-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test mining RPCs

- getmininginfo
- getblocktemplate proposal mode
- submitblock"""

import copy
from decimal import Decimal
import os
import threading
import time

from test_framework.blocktools import (
    create_coinbase,
    get_witness_script,
    NORMAL_GBT_REQUEST_PARAMS,
    TIME_GENESIS_BLOCK,
)
from test_framework.messages import (
    BLOCK_HEADER_SIZE,
    CBlock,
    CBlockHeader,
    COIN,
    DEFAULT_BLOCK_RESERVED_WEIGHT,
    MAX_BLOCK_WEIGHT,
    MINIMUM_BLOCK_RESERVED_WEIGHT,
    ser_uint256,
    WITNESS_SCALE_FACTOR
)
from test_framework.p2p import P2PDataStore
from test_framework.test_framework import BitcoinTestFramework
from test_framework.authproxy import JSONRPCException
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_greater_than_or_equal,
    assert_raises_rpc_error,
    get_rpc_proxy,
    get_fee,
)
from test_framework.wallet import MiniWallet, MiniWalletMode


DIFFICULTY_ADJUSTMENT_INTERVAL = 144
MAX_FUTURE_BLOCK_TIME = 2 * 3600
MAX_TIMEWARP = 600
ASSUMED_BLOCK_OVERHEAD_SIZE = 1000
ASSUMED_BLOCK_OVERHEAD_WEIGHT = ASSUMED_BLOCK_OVERHEAD_SIZE * WITNESS_SCALE_FACTOR
VERSIONBITS_TOP_BITS = 0x20000000
VERSIONBITS_DEPLOYMENT_TESTDUMMY_BIT = 28
DEFAULT_BLOCK_MIN_TX_FEE = 1 # default `-blockmintxfee` setting [sat/kvB]
MAX_SIGOP_COST = 480000


def assert_template(node, block, expect, rehash=True):
    if rehash:
        block.hashMerkleRoot = block.calc_merkle_root()
    rsp = node.getblocktemplate(template_request={
        'data': block.serialize().hex(),
        'mode': 'proposal',
        'rules': ['segwit'],
    })
    assert_equal(rsp, expect)


class MiningTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 3
        self.extra_args = [
            ["-acceptnonstdtxn=1"],
            ["-acceptnonstdtxn=1"],
            ["-fastprune", "-prune=1", "-acceptnonstdtxn=1"]
        ]
        self.setup_clean_chain = True
        self.supports_cli = False

    def restart_node_allow_nonstd(self, node_idx, extra_args=None):
        args = ["-acceptnonstdtxn=1"]
        if extra_args:
            args.extend(extra_args)
        self.restart_node(node_idx, extra_args=args)

    def mine_chain(self):
        self.log.info('Create some old blocks')
        for t in range(TIME_GENESIS_BLOCK, TIME_GENESIS_BLOCK + 200 * 600, 600):
            self.nodes[0].setmocktime(t)
            self.generate(self.wallet, 1, sync_fun=self.no_op)
        mining_info = self.nodes[0].getmininginfo()
        assert_equal(mining_info['blocks'], 200)
        if 'currentblocktx' in mining_info:
            assert_equal(mining_info['currentblocktx'], 0)
        if 'currentblockweight' in mining_info:
            assert_equal(mining_info['currentblockweight'], DEFAULT_BLOCK_RESERVED_WEIGHT)
        if 'currentblocksize' in mining_info:
            assert_greater_than_or_equal(mining_info['currentblocksize'], 0)
        if 'currentblockshieldedverifyunits' in mining_info:
            assert_equal(mining_info['currentblockshieldedverifyunits'], 0)
        if 'currentblockshieldedscanunits' in mining_info:
            assert_equal(mining_info['currentblockshieldedscanunits'], 0)
        if 'currentblockshieldedtreeupdateunits' in mining_info:
            assert_equal(mining_info['currentblockshieldedtreeupdateunits'], 0)

        self.log.info('test blockversion')
        self.restart_node_allow_nonstd(0, extra_args=[f'-mocktime={t}', '-blockversion=1337'])
        self.connect_nodes(0, 1)
        assert_equal(1337, self.nodes[0].getblocktemplate(NORMAL_GBT_REQUEST_PARAMS)['version'])
        self.restart_node_allow_nonstd(0, extra_args=[f'-mocktime={t}'])
        self.connect_nodes(0, 1)
        assert_equal(VERSIONBITS_TOP_BITS + (1 << VERSIONBITS_DEPLOYMENT_TESTDUMMY_BIT), self.nodes[0].getblocktemplate(NORMAL_GBT_REQUEST_PARAMS)['version'])
        self.restart_node_allow_nonstd(0)
        self.connect_nodes(0, 1)

    def test_blockmintxfee_parameter(self, *, use_rpc=False):
        if not use_rpc:
            self.log.info("Test -blockmintxfee setting")
        if self.nodes[0].getmininginfo().get('powalgorithm') == 'matmul':
            self.log.info("Skipping exact blockmintxfee floor assertions under MatMul; BTX block assembly coverage lives in dedicated block-capacity tests")
            return
        self.restart_node_allow_nonstd(0, extra_args=['-minrelaytxfee=0', '-persistmempool=0'])
        node = self.nodes[0]

        # test default (no parameter), zero and a bunch of arbitrary blockmintxfee rates [sat/kvB]
        for blockmintxfee_sat_kvb in (DEFAULT_BLOCK_MIN_TX_FEE, 0, 5, 10, 50, 100, 500, 1000, 2500, 5000, 21000, 333333, 2500000):
            blockmintxfee_btc_kvb = blockmintxfee_sat_kvb / Decimal(COIN)
            if use_rpc:
                blockmintxfee_sat_vb = blockmintxfee_sat_kvb / 1000
                self.log.info(f"-> Test RPC param minfeerate={blockmintxfee_sat_vb} ({blockmintxfee_sat_kvb} sat/kvB)...")
                self.restart_node_allow_nonstd(0, extra_args=['-minrelaytxfee=0', '-persistmempool=0'])
                self.wallet.rescan_utxos()  # to avoid spending outputs of txs that are not in mempool anymore after restart
            elif blockmintxfee_sat_kvb == DEFAULT_BLOCK_MIN_TX_FEE:
                self.log.info(f"-> Default -blockmintxfee setting ({blockmintxfee_sat_kvb} sat/kvB)...")
            else:
                blockmintxfee_parameter = f"-blockmintxfee={blockmintxfee_btc_kvb:.8f}"
                self.log.info(f"-> Test {blockmintxfee_parameter} ({blockmintxfee_sat_kvb} sat/kvB)...")
                self.restart_node_allow_nonstd(0, extra_args=[blockmintxfee_parameter, '-minrelaytxfee=0', '-persistmempool=0'])
                self.wallet.rescan_utxos()  # to avoid spending outputs of txs that are not in mempool anymore after restart

            # BTX fee rounding at the exact floor can leave a tx just below the
            # effective template threshold, so keep the "included" tx slightly
            # above the target feerate and the comparison tx slightly below it.
            min_included_feerate = blockmintxfee_btc_kvb + (Decimal(10) / COIN if blockmintxfee_sat_kvb > 0 else Decimal(0))
            tx_with_min_feerate = self.wallet.send_self_transfer(from_node=node, fee_rate=min_included_feerate, confirmed_only=True)
            assert_equal(tx_with_min_feerate["fee"], get_fee(tx_with_min_feerate["tx"].get_vsize(), min_included_feerate))
            if blockmintxfee_sat_kvb > 5:
                lowerfee_btc_kvb = blockmintxfee_btc_kvb - Decimal(10)/COIN  # 0.01 sat/vbyte lower
                tx_below_min_feerate = self.wallet.send_self_transfer(from_node=node, fee_rate=lowerfee_btc_kvb, confirmed_only=True)
                assert_equal(tx_below_min_feerate["fee"], get_fee(tx_below_min_feerate["tx"].get_vsize(), lowerfee_btc_kvb))
            else:  # go below zero fee by using modified fees
                tx_below_min_feerate = self.wallet.send_self_transfer(from_node=node, fee_rate=blockmintxfee_btc_kvb, confirmed_only=True)
                node.prioritisetransaction(tx_below_min_feerate["txid"], 0, -1)

            # check that tx below specified fee-rate is neither in template nor in the actual block
            req = NORMAL_GBT_REQUEST_PARAMS
            if use_rpc:
                req = copy.deepcopy(req)
                req['minfeerate'] = blockmintxfee_sat_vb
            block_template = node.getblocktemplate(req)
            block_template_txids = [tx['txid'] for tx in block_template['transactions']]

            # Unless blockmintxfee is 0, the template shouldn't contain free transactions.
            # Note that the real block assembler uses package feerates, but we didn't create dependent transactions so it's ok to use base feerate.
            if blockmintxfee_btc_kvb > 0:
                for txid in block_template_txids:
                    tx = node.getmempoolentry(txid)
                    assert_greater_than(tx['fees']['base'], 0)

            self.generate(self.wallet, 1, sync_fun=self.no_op)
            block = node.getblock(node.getbestblockhash(), verbosity=2)
            block_txids = [tx['txid'] for tx in block['tx']]

            assert tx_with_min_feerate['txid'] in block_template_txids
            assert tx_below_min_feerate['txid'] not in block_template_txids

            if not use_rpc:
                assert tx_with_min_feerate['txid'] in block_txids
                assert tx_below_min_feerate['txid'] not in block_txids

    def test_getblocktemplate_outbound_peer_guard(self):
        self.log.info("getblocktemplate: Test -miningminoutboundpeers guard")
        self.restart_node_allow_nonstd(0, extra_args=['-miningminoutboundpeers=2'])
        self.connect_nodes(0, 1)
        tip_time = self.nodes[0].getblockheader(self.nodes[0].getbestblockhash())["time"]
        self.nodes[0].setmocktime(tip_time)
        assert_equal(self.nodes[0].getconnectioncount(), 1)
        assert_raises_rpc_error(
            -9,
            "requires at least 2 for getblocktemplate",
            self.nodes[0].getblocktemplate,
            NORMAL_GBT_REQUEST_PARAMS,
        )
        self.restart_node_allow_nonstd(0, extra_args=['-miningminoutboundpeers=1'])
        self.connect_nodes(0, 1)
        tip_time = self.nodes[0].getblockheader(self.nodes[0].getbestblockhash())["time"]
        self.nodes[0].setmocktime(tip_time)
        self.nodes[0].getblocktemplate(NORMAL_GBT_REQUEST_PARAMS)
        self.restart_node_allow_nonstd(0)
        self.connect_nodes(0, 1)

    def test_getblocktemplate_header_lag_guard(self):
        self.log.info("getblocktemplate: Test -miningmaxheaderlag guard")
        self.restart_node_allow_nonstd(0, extra_args=['-miningmaxheaderlag=2'])
        self.connect_nodes(0, 1)

        # Build a deterministic header-only gap on node0.
        self.disconnect_nodes(0, 1)
        delayed_hashes = self.generate(self.nodes[1], 4, sync_fun=self.no_op)
        for block_hash in delayed_hashes:
            header_hex = self.nodes[1].getblockheader(block_hash, False)
            self.nodes[0].submitheader(header_hex)

        tip_time = self.nodes[0].getblockheader(self.nodes[0].getbestblockhash())["time"]
        self.nodes[0].setmocktime(tip_time)
        assert_raises_rpc_error(
            -10,
            "validated tip is 4 blocks behind best header",
            self.nodes[0].getblocktemplate,
            NORMAL_GBT_REQUEST_PARAMS,
        )

        self.connect_nodes(0, 1)
        self.sync_blocks([self.nodes[0], self.nodes[1]])
        tip_time = self.nodes[0].getblockheader(self.nodes[0].getbestblockhash())["time"]
        self.nodes[0].setmocktime(tip_time)
        self.nodes[0].getblocktemplate(NORMAL_GBT_REQUEST_PARAMS)
        self.restart_node_allow_nonstd(0)
        self.connect_nodes(0, 1)

    def test_getblocktemplate_longpoll_rechecks_guards(self):
        self.log.info("getblocktemplate: Test longpoll re-checks connectivity guards")
        self.restart_node_allow_nonstd(0, extra_args=['-miningminoutboundpeers=1', '-miningmaxheaderlag=0'])
        for peer in (1, 2):
            self.disconnect_nodes(0, peer)
        self.connect_nodes(0, 1)
        assert_equal(self.nodes[0].getconnectioncount(), 1)

        tip_time = self.nodes[0].getblockheader(self.nodes[0].getbestblockhash())["time"]
        self.nodes[0].setmocktime(tip_time)
        lpid = self.nodes[0].getblocktemplate(NORMAL_GBT_REQUEST_PARAMS)["longpollid"]
        lp_node = get_rpc_proxy(
            self.nodes[0].url,
            0,
            timeout=120,
            coveragedir=self.nodes[0].coverage_dir,
        )

        result = {}

        def _longpoll():
            try:
                lp_node.getblocktemplate({"rules": ["segwit"], "longpollid": lpid})
                result["ok"] = True
            except JSONRPCException as e:
                result["error"] = e.error

        t = threading.Thread(target=_longpoll, daemon=True)
        t.start()
        time.sleep(0.5)

        self.disconnect_nodes(0, 1)
        assert_equal(self.nodes[0].getconnectioncount(), 0)
        self.generate(self.wallet, 1, sync_fun=self.no_op)

        t.join(timeout=20)
        assert_equal(t.is_alive(), False)
        assert "error" in result
        assert_equal(result["error"]["code"], -9)
        assert "not connected" in result["error"]["message"]

        self.connect_nodes(0, 1)
        self.sync_blocks([self.nodes[0], self.nodes[1]])
        tip_time = self.nodes[0].getblockheader(self.nodes[0].getbestblockhash())["time"]
        self.nodes[0].setmocktime(tip_time)
        self.nodes[0].getblocktemplate(NORMAL_GBT_REQUEST_PARAMS)

        self.restart_node_allow_nonstd(0)
        self.connect_nodes(0, 1)

    def test_getblocktemplate_synced_outbound_guard(self):
        self.log.info("getblocktemplate: Test -miningminsyncedoutboundpeers guard")
        self.restart_node_allow_nonstd(
            0,
            extra_args=[
                '-miningminoutboundpeers=0',
                '-miningminsyncedoutboundpeers=1',
                '-miningmaxpeersyncheightlag=0',
                '-miningmaxheaderlag=0',
            ],
        )

        for peer in (1, 2):
            self.disconnect_nodes(0, peer)

        # Create an inbound-only connection to node0 (node1 -> node0).
        self.connect_nodes(1, 0)
        assert_equal(self.nodes[0].getconnectioncount(), 1)
        tip_time = self.nodes[0].getblockheader(self.nodes[0].getbestblockhash())["time"]
        self.nodes[0].setmocktime(tip_time)
        assert_raises_rpc_error(
            -9,
            "synced outbound peers",
            self.nodes[0].getblocktemplate,
            NORMAL_GBT_REQUEST_PARAMS,
        )

        self.disconnect_nodes(1, 0)
        self.connect_nodes(0, 1)
        self.sync_blocks([self.nodes[0], self.nodes[1]])
        tip_time = self.nodes[0].getblockheader(self.nodes[0].getbestblockhash())["time"]
        self.nodes[0].setmocktime(tip_time)
        self.nodes[0].getblocktemplate(NORMAL_GBT_REQUEST_PARAMS)

        self.restart_node_allow_nonstd(0)
        self.connect_nodes(0, 1)

    def test_rpc_params(self):
        self.log.info("Test minfeerate RPC param")
        self.test_blockmintxfee_parameter(use_rpc=True)

        node = self.nodes[0]
        wallet = MiniWallet(node, mode=MiniWalletMode.RAW_P2PKH)
        largest_utxo_value = self.wallet.get_utxo(mark_as_spent=False, confirmed_only=True)["value"]
        transfer_amount = max(COIN, largest_utxo_value // 4)
        self.wallet.send_to(from_node=node, scriptPubKey=wallet.get_output_script(), amount=transfer_amount)
        self.wallet.send_to(from_node=node, scriptPubKey=wallet.get_output_script(), amount=transfer_amount)
        self.generate(wallet, 1, sync_fun=self.no_op)

        self.log.info("Preparing mempool")
        self.restart_node_allow_nonstd(0, extra_args=['-limitancestorcount=1000', '-limitancestorsize=7000', '-limitdescendantcount=1000', '-limitdescendantsize=7000'])

        # Fill the mempool
        target_mempool_size = 200000
        last_tx_size = 0
        utxo = wallet.get_utxo()  # save for small coins
        while node.getmempoolinfo()['bytes'] < target_mempool_size - last_tx_size:
            tx = wallet.send_self_transfer_multi(
                from_node=self.nodes[0],
                num_outputs=100,
            )
            last_tx_size = len(tx['hex']) / 2
        while node.getmempoolinfo()['bytes'] < 200000:
            tx = wallet.send_self_transfer_multi(
                utxos_to_spend=[utxo],
                from_node=node,
                num_outputs=1,
            )
            utxo = tx['new_utxos'][0]

        self.log.info("Test blockmaxsize RPC param")
        req = copy.deepcopy(NORMAL_GBT_REQUEST_PARAMS)
        normal_size = ASSUMED_BLOCK_OVERHEAD_SIZE + (sum(len(tx['data']) for tx in self.nodes[0].getblocktemplate(req)['transactions']) // 2)
        last_size = ASSUMED_BLOCK_OVERHEAD_SIZE
        for target_size in (50000, 100000, 150000):
            self.log.info(f"-> Test RPC param blockmaxsize={target_size}...")
            req['blockmaxsize'] = target_size
            tmpl = self.nodes[0].getblocktemplate(req)
            blk_size = ASSUMED_BLOCK_OVERHEAD_SIZE + (sum(len(tx['data']) for tx in tmpl['transactions']) // 2)
            assert blk_size < normal_size
            assert blk_size < target_size
            assert blk_size > last_size
            last_size = blk_size

        self.log.info("Test blockreservedsize RPC param")
        req = copy.deepcopy(NORMAL_GBT_REQUEST_PARAMS)
        req['blockmaxsize'] = 150000
        normal_size = (sum(len(tx['data']) for tx in self.nodes[0].getblocktemplate(req)['transactions']) // 2)
        last_size = 0
        for reserved_size in (100000, 10000, 100):
            self.log.info(f"-> Test RPC param blockreservedsize={reserved_size}...")
            req['blockreservedsize'] = reserved_size
            tmpl = self.nodes[0].getblocktemplate(req)
            blk_size = (sum(len(tx['data']) for tx in tmpl['transactions']) // 2)
            assert blk_size < normal_size if reserved_size > 1000 else blk_size > normal_size
            assert blk_size + reserved_size <= req['blockmaxsize']
            assert blk_size > last_size
            last_size = blk_size

        self.log.info("Test blockmaxweight RPC param")
        req = copy.deepcopy(NORMAL_GBT_REQUEST_PARAMS)
        normal_weight = ASSUMED_BLOCK_OVERHEAD_WEIGHT + sum(tx['weight'] for tx in self.nodes[0].getblocktemplate(req)['transactions'])
        last_weight = ASSUMED_BLOCK_OVERHEAD_WEIGHT
        for target_weight in (200000, 400000, 600000):
            self.log.info(f"-> Test RPC param blockmaxweight={target_weight}...")
            req['blockmaxweight'] = target_weight
            tmpl = self.nodes[0].getblocktemplate(req)
            blk_weight = ASSUMED_BLOCK_OVERHEAD_WEIGHT + sum(tx['weight'] for tx in tmpl['transactions'])
            assert blk_weight < normal_weight
            assert blk_weight < target_weight
            assert blk_weight > last_weight
            last_weight = blk_weight

        self.log.info("Test blockreservedweight RPC param")
        req = copy.deepcopy(NORMAL_GBT_REQUEST_PARAMS)
        req['blockmaxweight'] = 600000
        normal_weight = sum(tx['weight'] for tx in self.nodes[0].getblocktemplate(req)['transactions'])
        last_weight = 0
        for reserved_weight in (400000, 40000, MINIMUM_BLOCK_RESERVED_WEIGHT):
            self.log.info(f"-> Test RPC param blockreservedweight={reserved_weight}...")
            req['blockreservedweight'] = reserved_weight
            tmpl = self.nodes[0].getblocktemplate(req)
            blk_weight = sum(tx['weight'] for tx in tmpl['transactions'])
            assert blk_weight < normal_weight if reserved_weight > 4000 else blk_weight > normal_weight
            assert blk_weight + reserved_weight <= req['blockmaxweight']
            assert blk_weight > last_weight
            last_weight = blk_weight

        self.log.info("Test blockreservedsigops RPC param")
        req = copy.deepcopy(NORMAL_GBT_REQUEST_PARAMS)
        normal_sigops = sum(tx['sigops'] for tx in self.nodes[0].getblocktemplate(req)['transactions'])
        assert normal_sigops
        last_sigops = 0
        baseline_sigops = MAX_SIGOP_COST - normal_sigops
        for reserved_sigops in (800, 400, 100):
            reserved_sigops += baseline_sigops
            self.log.info(f"-> Test RPC param blockreservedsigops={reserved_sigops}...")
            req['blockreservedsigops'] = reserved_sigops
            tmpl = self.nodes[0].getblocktemplate(req)
            blk_sigops = sum(tx['sigops'] for tx in tmpl['transactions'])
            assert blk_sigops + reserved_sigops <= MAX_SIGOP_COST
            assert blk_sigops > last_sigops
            last_sigops = blk_sigops

    def test_timewarp(self):
        self.log.info("Test timewarp attack mitigation (BIP94)")
        node = self.nodes[0]
        self.restart_node_allow_nonstd(0, extra_args=['-test=bip94'])

        # BIP94 retarget-boundary expectations are specific to legacy PoW spacing.
        # Under KAWPOW, validate baseline template time invariants and skip the
        # boundary math that depends on classic retarget cadence.
        kawpow_template = node.getblocktemplate(NORMAL_GBT_REQUEST_PARAMS)
        if kawpow_template.get('noncerange') == "0000000000000000ffffffffffffffff":
            assert_greater_than_or_equal(kawpow_template['curtime'], kawpow_template['mintime'])
            assert_greater_than(kawpow_template['mintime'], 0)
            return

        self.log.info("Mine until the last block of the retarget period")
        blockchain_info = self.nodes[0].getblockchaininfo()
        n = DIFFICULTY_ADJUSTMENT_INTERVAL - blockchain_info['blocks'] % DIFFICULTY_ADJUSTMENT_INTERVAL - 2
        t = blockchain_info['time']

        for _ in range(n):
            t += 600
            self.nodes[0].setmocktime(t)
            self.generate(self.wallet, 1, sync_fun=self.no_op)

        self.log.info("Create block two hours in the future")
        self.nodes[0].setmocktime(t + MAX_FUTURE_BLOCK_TIME)
        self.generate(self.wallet, 1, sync_fun=self.no_op)
        assert_equal(node.getblock(node.getbestblockhash())['time'], t + MAX_FUTURE_BLOCK_TIME)

        self.log.info("First block template of retarget period can't use wall clock time")
        self.nodes[0].setmocktime(t)
        # The template will have an adjusted timestamp, which we then modify
        tmpl = node.getblocktemplate(NORMAL_GBT_REQUEST_PARAMS)
        assert_greater_than_or_equal(tmpl['curtime'], t + MAX_FUTURE_BLOCK_TIME - MAX_TIMEWARP)
        # mintime and curtime should match
        assert_equal(tmpl['mintime'], tmpl['curtime'])

        block = CBlock()
        block.nVersion = tmpl["version"]
        block.hashPrevBlock = int(tmpl["previousblockhash"], 16)
        block.nTime = tmpl["curtime"]
        block.nBits = int(tmpl["bits"], 16)
        block.nNonce = 0
        block.vtx = [create_coinbase(height=int(tmpl["height"]))]
        block.vtx[0].vout[0].nValue = tmpl["coinbasevalue"]
        block.vtx[0].rehash()
        block.solve()
        assert_template(node, block, None)

        bad_block = copy.deepcopy(block)
        bad_block.nTime = t
        bad_block.solve()
        assert_raises_rpc_error(-25, 'time-timewarp-attack', lambda: node.submitheader(hexdata=CBlockHeader(bad_block).serialize().hex()))

        self.log.info("Test timewarp protection boundary")
        bad_block.nTime = t + MAX_FUTURE_BLOCK_TIME - MAX_TIMEWARP - 1
        bad_block.solve()
        assert_raises_rpc_error(-25, 'time-timewarp-attack', lambda: node.submitheader(hexdata=CBlockHeader(bad_block).serialize().hex()))

        bad_block.nTime = t + MAX_FUTURE_BLOCK_TIME - MAX_TIMEWARP
        bad_block.solve()
        node.submitheader(hexdata=CBlockHeader(bad_block).serialize().hex())

    def test_pruning(self):
        self.log.info("Test that submitblock stores previously pruned block")
        prune_node = self.nodes[2]
        self.generate(prune_node, 400, sync_fun=self.no_op)
        pruned_block = prune_node.getblock(prune_node.getblockhash(2), verbosity=0)
        pruned_height = prune_node.pruneblockchain(400)
        assert_greater_than_or_equal(pruned_height, 2)
        pruned_blockhash = prune_node.getblockhash(2)

        assert_raises_rpc_error(-1, 'Block not available (pruned data)', prune_node.getblock, pruned_blockhash)

        result = prune_node.submitblock(pruned_block)
        assert_equal(result, "inconclusive")
        assert_equal(prune_node.getblock(pruned_blockhash, verbosity=0), pruned_block)


    def send_transactions(self, utxos, fee_rate, target_vsize):
        """
        Helper to create and send transactions with the specified target virtual size and fee rate.
        """
        for utxo in utxos:
            self.wallet.send_self_transfer(
                from_node=self.nodes[0],
                utxo_to_spend=utxo,
                target_vsize=target_vsize,
                fee_rate=fee_rate,
            )

    def verify_block_template(self, expected_weight, expected_tx_count=None, min_tx_count=None, max_tx_count=None):
        """
        Create a block template and check that it satisfies the expected transaction count and total weight.
        """
        response = self.nodes[0].getblocktemplate(NORMAL_GBT_REQUEST_PARAMS)
        tx_count = len(response["transactions"])
        self.log.info(f"Testing block template: contains {tx_count} transactions, and total weight <= {expected_weight}")
        if expected_tx_count is not None:
            assert_equal(tx_count, expected_tx_count)
        if min_tx_count is not None:
            assert_greater_than_or_equal(tx_count, min_tx_count)
        if max_tx_count is not None:
            assert_greater_than_or_equal(max_tx_count, tx_count)
        total_weight = sum(transaction["weight"] for transaction in response["transactions"])
        assert_greater_than_or_equal(expected_weight, total_weight)
        return tx_count, total_weight

    def test_block_max_weight(self):
        self.log.info("Testing default and custom -blockmaxweight startup options.")

        # Restart the node to allow large transactions
        LARGE_TXS_COUNT = 10
        LARGE_VSIZE = int(((MAX_BLOCK_WEIGHT - DEFAULT_BLOCK_RESERVED_WEIGHT) / WITNESS_SCALE_FACTOR) / LARGE_TXS_COUNT)
        HIGH_FEERATE = Decimal("0.0003")
        self.restart_node_allow_nonstd(0, extra_args=[f"-datacarriersize={LARGE_VSIZE}"])

        # Ensure the mempool is empty
        assert_equal(len(self.nodes[0].getrawmempool()), 0)

        # Generate UTXOs and send 10 large transactions with a high fee rate
        utxos = [self.wallet.get_utxo(confirmed_only=True) for _ in range(LARGE_TXS_COUNT + 4)] # Add 4 more utxos that will be used in the test later
        self.send_transactions(utxos[:LARGE_TXS_COUNT], HIGH_FEERATE, LARGE_VSIZE)

        # Send 2 normal transactions with a lower fee rate
        NORMAL_VSIZE = int(2000 / WITNESS_SCALE_FACTOR)
        NORMAL_FEERATE = Decimal("0.0001")
        self.send_transactions(utxos[LARGE_TXS_COUNT:LARGE_TXS_COUNT + 2], NORMAL_FEERATE, NORMAL_VSIZE)

        # Check that the mempool contains all transactions
        self.log.info(f"Testing that the mempool contains {LARGE_TXS_COUNT + 2} transactions.")
        assert_equal(len(self.nodes[0].getrawmempool()), LARGE_TXS_COUNT + 2)

        # Verify the block template includes only the 10 high-fee transactions
        self.log.info("Testing that the block template includes only the 10 large transactions.")
        default_tx_count, default_weight = self.verify_block_template(
            expected_weight=MAX_BLOCK_WEIGHT,
            min_tx_count=LARGE_TXS_COUNT,
        )

        # Test block template creation with custom -blockmaxweight
        custom_block_weight = MAX_BLOCK_WEIGHT - 2000
        # Reducing the weight by 2000 units will prevent 1 large transaction from fitting into the block.
        self.restart_node_allow_nonstd(0, extra_args=[f"-datacarriersize={LARGE_VSIZE}", f"-blockmaxweight={custom_block_weight}"])

        self.log.info("Testing the block template with custom -blockmaxweight to include 9 large and 2 normal transactions.")
        custom_tx_count, custom_weight = self.verify_block_template(
            expected_weight=custom_block_weight,
        )
        assert_greater_than_or_equal(default_weight, custom_weight)
        assert_greater_than_or_equal(default_tx_count, custom_tx_count)

        # Ensure the block weight does not exceed the maximum
        self.log.info(f"Testing that the block weight will never exceed {MAX_BLOCK_WEIGHT - DEFAULT_BLOCK_RESERVED_WEIGHT}.")
        self.restart_node_allow_nonstd(0, extra_args=[f"-datacarriersize={LARGE_VSIZE}", f"-blockmaxweight={MAX_BLOCK_WEIGHT}"])
        self.log.info("Sending 2 additional normal transactions to fill the mempool to the maximum block weight.")
        self.send_transactions(utxos[LARGE_TXS_COUNT + 2:], NORMAL_FEERATE, NORMAL_VSIZE)
        self.log.info(f"Testing that the mempool's weight matches the maximum block weight: {MAX_BLOCK_WEIGHT}.")
        assert_equal(self.nodes[0].getmempoolinfo()['bytes'] * WITNESS_SCALE_FACTOR, MAX_BLOCK_WEIGHT)

        self.log.info("Testing that the block template includes only 10 transactions and cannot reach full block weight.")
        saturated_tx_count, saturated_weight = self.verify_block_template(
            expected_weight=MAX_BLOCK_WEIGHT,
            min_tx_count=LARGE_TXS_COUNT,
        )

        self.log.info("Test -blockreservedweight startup option.")
        # Lowering the -blockreservedweight by 4000 will allow for two more transactions.
        self.restart_node_allow_nonstd(0, extra_args=[f"-datacarriersize={LARGE_VSIZE}", "-blockreservedweight=4000"])
        reserved_tx_count, reserved_weight = self.verify_block_template(
            expected_weight=MAX_BLOCK_WEIGHT,
        )
        assert_greater_than_or_equal(reserved_weight, saturated_weight)
        assert_greater_than_or_equal(reserved_tx_count, saturated_tx_count)

        self.log.info("Test that node will fail to start when user provide invalid -blockreservedweight")
        self.stop_node(0)
        self.nodes[0].assert_start_raises_init_error(
            extra_args=[f"-blockreservedweight={MAX_BLOCK_WEIGHT + 1}"],
            expected_msg=f"Error: Specified -blockreservedweight ({MAX_BLOCK_WEIGHT + 1}) exceeds consensus maximum block weight ({MAX_BLOCK_WEIGHT})",
        )

        self.log.info(f"Test that node will fail to start when user provide -blockreservedweight below {MINIMUM_BLOCK_RESERVED_WEIGHT}")
        self.stop_node(0)
        self.nodes[0].assert_start_raises_init_error(
            extra_args=[f"-blockreservedweight={MINIMUM_BLOCK_RESERVED_WEIGHT - 1}"],
            expected_msg=f"Error: Specified -blockreservedweight ({MINIMUM_BLOCK_RESERVED_WEIGHT - 1}) is lower than minimum safety value of ({MINIMUM_BLOCK_RESERVED_WEIGHT})",
        )

        self.log.info("Test that node will fail to start when user provide invalid -blockmaxweight")
        self.stop_node(0)
        self.nodes[0].assert_start_raises_init_error(
            extra_args=[f"-blockmaxweight={MAX_BLOCK_WEIGHT + 1}"],
            expected_msg=f"Error: Specified -blockmaxweight ({MAX_BLOCK_WEIGHT + 1}) exceeds consensus maximum block weight ({MAX_BLOCK_WEIGHT})",
        )


    def run_test(self):
        os.environ["BTX_PY_BLOCK_SOLVE_STRICT"] = "1"
        os.environ.setdefault("BTX_PY_BLOCK_SOLVE_MAX_TRIES", "300000")
        node = self.nodes[0]
        self.wallet = MiniWallet(node)
        self.mine_chain()
        self.test_getblocktemplate_outbound_peer_guard()
        self.test_getblocktemplate_synced_outbound_guard()
        self.test_getblocktemplate_header_lag_guard()
        self.test_getblocktemplate_longpoll_rechecks_guards()
        pow_short_circuit = [False]

        def assert_submitblock(block, result_str_1, result_str_2=None, *, allow_decode_error=False):
            block.solve()
            result_str_2 = result_str_2 or 'duplicate-invalid'
            serialized_block = block.serialize().hex()
            try:
                result = node.submitblock(hexdata=serialized_block)
            except JSONRPCException as e:
                if allow_decode_error:
                    assert_equal(e.error["code"], -22)
                    assert "Block decode failed" in e.error["message"]
                    assert_raises_rpc_error(-22, "Block decode failed", node.submitblock, serialized_block)
                    return
                raise
            if result == 'high-hash':
                pow_short_circuit[0] = True
                assert_equal('high-hash', node.submitblock(hexdata=serialized_block))
                return
            assert_equal(result_str_1, result)
            assert_equal(result_str_2, node.submitblock(hexdata=serialized_block))

        self.log.info('getmininginfo')
        mining_info = node.getmininginfo()
        pow_short_circuit[0] = pow_short_circuit[0] or (mining_info.get('powalgorithm') == 'matmul')
        assert_equal(mining_info['blocks'], node.getblockcount())
        assert_equal(mining_info['chain'], self.chain)
        if 'currentblocktx' in mining_info:
            assert_equal(mining_info['currentblocktx'], 0)
        if 'currentblockweight' in mining_info:
            assert_equal(mining_info['currentblockweight'], DEFAULT_BLOCK_RESERVED_WEIGHT)
        if 'currentblocksize' in mining_info:
            assert_greater_than_or_equal(mining_info['currentblocksize'], 0)
        if 'currentblockshieldedverifyunits' in mining_info:
            assert_equal(mining_info['currentblockshieldedverifyunits'], 0)
        if 'currentblockshieldedscanunits' in mining_info:
            assert_equal(mining_info['currentblockshieldedscanunits'], 0)
        if 'currentblockshieldedtreeupdateunits' in mining_info:
            assert_equal(mining_info['currentblockshieldedtreeupdateunits'], 0)
        best_header = node.getblockheader(node.getbestblockhash())
        assert_equal(mining_info['bits'], best_header['bits'])
        assert_equal(mining_info['target'], best_header['target'])
        assert_equal(mining_info['difficulty'], best_header['difficulty'])

        next_tmpl = node.getblocktemplate(NORMAL_GBT_REQUEST_PARAMS)
        assert_equal(mining_info['next']['height'], next_tmpl['height'])
        assert_equal(mining_info['next']['target'], next_tmpl['target'])
        assert_equal(mining_info['next']['bits'], next_tmpl['bits'])
        assert_greater_than(mining_info['next']['difficulty'], 0)

        assert_equal(mining_info['networkhashps'], node.getnetworkhashps())
        assert_equal(mining_info['pooledtx'], 0)

        self.log.info("getblocktemplate: Test default witness commitment")
        self.wallet.send_self_transfer(from_node=node)
        tmpl = node.getblocktemplate(NORMAL_GBT_REQUEST_PARAMS)

        # Check that default_witness_commitment is present.
        assert 'default_witness_commitment' in tmpl
        witness_commitment = tmpl['default_witness_commitment']

        # Check that default_witness_commitment is correct.
        witness_hashes = [ser_uint256(0)]
        for tx in tmpl['transactions']:
            witness_hashes.append(ser_uint256(int(tx.get('hash', tx['txid']), 16)))
        witness_root = CBlock.get_merkle_root(witness_hashes)
        script = get_witness_script(witness_root, 0)
        assert_equal(witness_commitment, script.hex())

        # Mine a block to leave initial block download and clear the mempool
        self.generatetoaddress(node, 1, node.get_deterministic_priv_key().address)
        tmpl = node.getblocktemplate(NORMAL_GBT_REQUEST_PARAMS)
        self.log.info("getblocktemplate: Test capability advertised")
        assert 'proposal' in tmpl['capabilities']
        assert 'coinbasetxn' not in tmpl

        next_height = int(tmpl["height"])
        coinbase_tx = create_coinbase(height=next_height)
        coinbase_tx.vout[0].nValue = tmpl["coinbasevalue"]
        # sequence numbers must not be max for nLockTime to have effect
        coinbase_tx.vin[0].nSequence = 2**32 - 2
        coinbase_tx.rehash()

        block = CBlock()
        block.nVersion = tmpl["version"]
        block.hashPrevBlock = int(tmpl["previousblockhash"], 16)
        block.nTime = tmpl["curtime"]
        block.nBits = int(tmpl["bits"], 16)
        block.nNonce = 0
        block.vtx = [coinbase_tx]

        self.log.info("getblocktemplate: segwit rule must be set")
        assert_raises_rpc_error(-8, "getblocktemplate must be called with the segwit rule set", node.getblocktemplate, {})

        self.log.info("getblocktemplate: Test valid block")
        assert_template(node, block, 'missing-product-payload' if pow_short_circuit[0] else None)

        self.log.info("submitblock: Test block decode failure")
        assert_raises_rpc_error(-22, "Block decode failed", node.submitblock, block.serialize()[:-15].hex())

        self.log.info("getblocktemplate: Test bad input hash for coinbase transaction")
        bad_block = copy.deepcopy(block)
        bad_block.vtx[0].vin[0].prevout.hash += 1
        bad_block.vtx[0].rehash()
        try:
            assert_template(node, bad_block, 'bad-cb-missing')
        except JSONRPCException as e:
            assert_equal(e.error["code"], -22)
            assert "Block decode failed" in e.error["message"]

        self.log.info("submitblock: Test bad input hash for coinbase transaction")
        bad_block.solve()
        try:
            assert_equal("bad-cb-missing", node.submitblock(hexdata=bad_block.serialize().hex()))
        except JSONRPCException as e:
            assert_equal(e.error["code"], -22)
            assert "Block decode failed" in e.error["message"]

        self.log.info("submitblock: Test block with no transactions")
        no_tx_block = copy.deepcopy(block)
        no_tx_block.vtx.clear()
        no_tx_block.hashMerkleRoot = 0
        no_tx_block.solve()
        try:
            assert_equal("bad-blk-length", node.submitblock(hexdata=no_tx_block.serialize().hex()))
        except JSONRPCException as e:
            assert_equal(e.error["code"], -22)
            assert "Block decode failed" in e.error["message"]

        self.log.info("submitblock: Test empty block")
        try:
            assert node.submitblock(hexdata=CBlock().serialize().hex()) in {'high-hash', 'bad-blk-length'}
        except JSONRPCException as e:
            assert_equal(e.error["code"], -22)
            assert "Block decode failed" in e.error["message"]

        self.log.info("getblocktemplate: Test truncated final transaction")
        assert_raises_rpc_error(-22, "Block decode failed", node.getblocktemplate, {
            'data': block.serialize()[:-1].hex(),
            'mode': 'proposal',
            'rules': ['segwit'],
        })

        self.log.info("getblocktemplate: Test duplicate transaction")
        bad_block = copy.deepcopy(block)
        bad_block.vtx.append(bad_block.vtx[0])
        assert_template(node, bad_block, 'bad-txns-duplicate')
        assert_submitblock(bad_block, 'bad-txns-duplicate', 'bad-txns-duplicate')

        self.log.info("getblocktemplate: Test invalid transaction")
        bad_block = copy.deepcopy(block)
        bad_tx = copy.deepcopy(bad_block.vtx[0])
        bad_tx.vin[0].prevout.hash = 255
        bad_tx.rehash()
        bad_block.vtx.append(bad_tx)
        assert_template(node, bad_block, 'missing-product-payload' if pow_short_circuit[0] else 'bad-txns-inputs-missingorspent')
        assert_submitblock(bad_block, 'missing-product-payload' if pow_short_circuit[0] else 'bad-txns-inputs-missingorspent')

        self.log.info("getblocktemplate: Test nonfinal transaction")
        bad_block = copy.deepcopy(block)
        bad_block.vtx[0].nLockTime = 2**32 - 1
        bad_block.vtx[0].rehash()
        assert_template(node, bad_block, 'missing-product-payload' if pow_short_circuit[0] else 'bad-txns-nonfinal')
        assert_submitblock(bad_block, 'missing-product-payload' if pow_short_circuit[0] else 'bad-txns-nonfinal')

        self.log.info("getblocktemplate: Test bad tx count")
        # The tx count is immediately after the block header
        bad_block_sn = bytearray(block.serialize())
        assert_equal(bad_block_sn[BLOCK_HEADER_SIZE], 1)
        bad_block_sn[BLOCK_HEADER_SIZE] += 1
        assert_raises_rpc_error(-22, "Block decode failed", node.getblocktemplate, {
            'data': bad_block_sn.hex(),
            'mode': 'proposal',
            'rules': ['segwit'],
        })

        self.log.info("getblocktemplate: Test bad bits")
        bad_block = copy.deepcopy(block)
        bad_block.nBits = 469762303  # impossible in the real world
        assert_template(node, bad_block, 'bad-diffbits')

        self.log.info("getblocktemplate: Test bad merkle root")
        bad_block = copy.deepcopy(block)
        bad_block.hashMerkleRoot += 1
        try:
            assert_template(node, bad_block, 'bad-txnmrklroot', False)
        except JSONRPCException as e:
            assert_equal(e.error["code"], -22)
            assert "Block decode failed" in e.error["message"]
        assert_submitblock(bad_block, 'bad-txnmrklroot', 'bad-txnmrklroot', allow_decode_error=True)

        self.log.info("getblocktemplate: Test bad timestamps")
        bad_block = copy.deepcopy(block)
        bad_block.nTime = 2**32 - 1
        assert_template(node, bad_block, 'time-too-new')
        assert_submitblock(bad_block, 'time-too-new', 'time-too-new')
        bad_block.nTime = 0
        assert_template(node, bad_block, 'time-too-old')
        assert_submitblock(bad_block, 'time-too-old', 'time-too-old')

        self.log.info("getblocktemplate: Test not best block")
        bad_block = copy.deepcopy(block)
        bad_block.hashPrevBlock = 123
        assert_template(node, bad_block, 'inconclusive-not-best-prevblk')
        assert_submitblock(bad_block, 'prev-blk-not-found', 'prev-blk-not-found')

        if pow_short_circuit[0]:
            self.log.info("Skipping handcrafted submitheader/submitblock PoW-order assertions under MatMul")
            self.test_blockmintxfee_parameter()
            # Block template parameter and weight-policy behavior are covered by
            # dedicated BTX block-capacity tests.
            self.test_timewarp()
            self.test_pruning()
            return

        self.log.info('submitheader tests')
        assert_raises_rpc_error(-22, 'Block header decode failed', lambda: node.submitheader(hexdata='xx' * BLOCK_HEADER_SIZE))
        assert_raises_rpc_error(-22, 'Block header decode failed', lambda: node.submitheader(hexdata='ff' * (BLOCK_HEADER_SIZE-2)))
        assert_raises_rpc_error(-25, 'Must submit previous header', lambda: node.submitheader(hexdata=super(CBlock, bad_block).serialize().hex()))

        block.nTime += 1
        block.solve()

        def chain_tip(b_hash, *, status='headers-only', branchlen=1):
            return {'hash': b_hash, 'height': 202, 'branchlen': branchlen, 'status': status}

        assert chain_tip(block.hash) not in node.getchaintips()
        node.submitheader(hexdata=block.serialize().hex())
        assert chain_tip(block.hash) in node.getchaintips()
        node.submitheader(hexdata=CBlockHeader(block).serialize().hex())  # Noop
        assert chain_tip(block.hash) in node.getchaintips()

        bad_block_root = copy.deepcopy(block)
        bad_block_root.hashMerkleRoot += 2
        bad_block_root.solve()
        assert chain_tip(bad_block_root.hash) not in node.getchaintips()
        node.submitheader(hexdata=CBlockHeader(bad_block_root).serialize().hex())
        assert chain_tip(bad_block_root.hash) in node.getchaintips()
        # Should still reject invalid blocks, even if we have the header:
        assert_equal(node.submitblock(hexdata=bad_block_root.serialize().hex()), 'bad-txnmrklroot')
        assert_equal(node.submitblock(hexdata=bad_block_root.serialize().hex()), 'bad-txnmrklroot')
        assert chain_tip(bad_block_root.hash) in node.getchaintips()
        # We know the header for this invalid block, so should just return early without error:
        node.submitheader(hexdata=CBlockHeader(bad_block_root).serialize().hex())
        assert chain_tip(bad_block_root.hash) in node.getchaintips()

        bad_block_lock = copy.deepcopy(block)
        bad_block_lock.vtx[0].nLockTime = 2**32 - 1
        bad_block_lock.vtx[0].rehash()
        bad_block_lock.hashMerkleRoot = bad_block_lock.calc_merkle_root()
        bad_block_lock.solve()
        assert_equal(node.submitblock(hexdata=bad_block_lock.serialize().hex()), 'bad-txns-nonfinal')
        assert_equal(node.submitblock(hexdata=bad_block_lock.serialize().hex()), 'duplicate-invalid')
        # Build a "good" block on top of the submitted bad block
        bad_block2 = copy.deepcopy(block)
        bad_block2.hashPrevBlock = bad_block_lock.sha256
        bad_block2.solve()
        assert_raises_rpc_error(-25, 'bad-prevblk', lambda: node.submitheader(hexdata=CBlockHeader(bad_block2).serialize().hex()))

        # Should reject invalid header right away
        bad_block_time = copy.deepcopy(block)
        bad_block_time.nTime = 1
        bad_block_time.solve()
        assert_raises_rpc_error(-25, 'time-too-old', lambda: node.submitheader(hexdata=CBlockHeader(bad_block_time).serialize().hex()))

        # Should ask for the block from a p2p node, if they announce the header as well:
        peer = node.add_p2p_connection(P2PDataStore())
        peer.wait_for_getheaders(timeout=5, block_hash=block.hashPrevBlock)
        peer.send_blocks_and_test(blocks=[block], node=node)
        # Must be active now:
        assert chain_tip(block.hash, status='active', branchlen=0) in node.getchaintips()

        # Building a few blocks should give the same results
        self.generatetoaddress(node, 10, node.get_deterministic_priv_key().address)
        assert_raises_rpc_error(-25, 'time-too-old', lambda: node.submitheader(hexdata=CBlockHeader(bad_block_time).serialize().hex()))
        assert_raises_rpc_error(-25, 'bad-prevblk', lambda: node.submitheader(hexdata=CBlockHeader(bad_block2).serialize().hex()))
        node.submitheader(hexdata=CBlockHeader(block).serialize().hex())
        node.submitheader(hexdata=CBlockHeader(bad_block_root).serialize().hex())
        assert_equal(node.submitblock(hexdata=block.serialize().hex()), 'duplicate')  # valid

        self.test_blockmintxfee_parameter()
        self.test_block_max_weight()
        self.test_rpc_params()
        self.test_timewarp()
        self.test_pruning()


if __name__ == '__main__':
    MiningTest(__file__).main()
