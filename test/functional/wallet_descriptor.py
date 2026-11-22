#!/usr/bin/env python3
# Copyright (c) 2019-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test descriptor wallet function."""

try:
    import sqlite3
except ImportError:
    pass

import concurrent.futures

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error
)
from test_framework.wallet_util import WalletUnlock


class WalletDescriptorTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [['-keypool=100']]
        self.wallet_names = []

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        self.skip_if_no_sqlite()
        self.skip_if_no_py_sqlite3()

    def test_concurrent_writes(self):
        self.log.info("Test sqlite concurrent writes are in the correct order")
        self.restart_node(0, extra_args=["-unsafesqlitesync=0"])
        self.nodes[0].createwallet(wallet_name="concurrency_source")
        source = self.nodes[0].get_wallet_rpc("concurrency_source")
        receive_desc = [d for d in source.listdescriptors(True)["descriptors"] if d["active"] and not d["internal"]][0]["desc"]
        source.unloadwallet()
        self.nodes[0].createwallet(wallet_name="concurrency", blank=True)
        wallet = self.nodes[0].get_wallet_rpc("concurrency")
        # First import a P2MR descriptor. Its PQ keys can only be derived from the
        # private seed, so topping up will require writing a ton to db
        wallet.importdescriptors([{"desc": receive_desc, "timestamp": "now", "active": True}])
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as thread:
            topup = thread.submit(wallet.keypoolrefill, newsize=1000)

            # Then while the topup is running, we need to do something that will call
            # ChainStateFlushed which will trigger a write to the db, hopefully at the
            # same time that the topup still has an open db transaction.
            self.nodes[0].cli.gettxoutsetinfo()
            assert_equal(topup.result(), None)

        wallet.unloadwallet()

        # Check that everything was written
        wallet_db = self.nodes[0].wallets_path / "concurrency" / self.wallet_data_filename
        conn = sqlite3.connect(wallet_db)
        with conn:
            # Retrieve the bestblock_nomerkle record
            bestblock_rec = conn.execute("SELECT value FROM main WHERE hex(key) = '1262657374626C6F636B5F6E6F6D65726B6C65'").fetchone()[0]
            # Retrieve the number of descriptor cache records
            # Since we store binary data, sqlite's comparison operators don't work everywhere
            # so just retrieve all records and process them ourselves.
            db_keys = conn.execute("SELECT key FROM main").fetchall()
            cache_records = len([k[0] for k in db_keys if b"walletdescriptorpqcache" in k[0]])
        conn.close()

        assert_equal(bestblock_rec[5:37][::-1].hex(), self.nodes[0].getbestblockhash())
        # One cached PQ key for each of the two key expressions (ML-DSA and SLH-DSA) per index
        assert_equal(cache_records, 2000)

    def run_test(self):
        if self.is_bdb_compiled():
            # Make a legacy wallet and check it is BDB
            self.nodes[0].createwallet(wallet_name="legacy1", descriptors=False)
            wallet_info = self.nodes[0].getwalletinfo()
            assert_equal(wallet_info['format'], 'bdb')
            self.nodes[0].unloadwallet("legacy1")
        else:
            self.log.warning("Skipping BDB test")

        # Make a descriptor wallet
        self.log.info("Making a descriptor wallet")
        self.nodes[0].createwallet(wallet_name="desc1", descriptors=True)

        # A BTX descriptor wallet has one active P2MR descriptor for receive and
        # one for change, so -keypool=100 gives 100 keys on each side.
        self.log.info("Checking wallet info")
        wallet_info = self.nodes[0].getwalletinfo()
        assert_equal(wallet_info['format'], 'sqlite')
        assert_equal(wallet_info['keypoolsize'], 100)
        assert_equal(wallet_info['keypoolsize_hd_internal'], 100)
        assert 'keypoololdest' not in wallet_info

        # Check that getnewaddress works
        self.log.info("Test that getnewaddress and getrawchangeaddress work")
        for address_type in [None, 'p2mr']:
            addr = self.nodes[0].getnewaddress("", address_type) if address_type else self.nodes[0].getnewaddress()
            addr_info = self.nodes[0].getaddressinfo(addr)
            assert addr_info['parent_desc'].startswith('mr(pqhd([')
            assert '/87h/1h/0h/0]/*)' in addr_info['parent_desc']
            assert_equal(addr_info['ischange'], False)

            addr = self.nodes[0].getrawchangeaddress(address_type) if address_type else self.nodes[0].getrawchangeaddress()
            addr_info = self.nodes[0].getaddressinfo(addr)
            assert addr_info['parent_desc'].startswith('mr(pqhd([')
            assert '/87h/1h/0h/1]/*)' in addr_info['parent_desc']
            assert_equal(addr_info['ischange'], True)

        self.log.info("Test that non-P2MR address types are refused")
        for address_type in ['legacy', 'p2sh-segwit', 'bech32', 'bech32m']:
            assert_raises_rpc_error(-8, "Only address type 'p2mr' is supported", self.nodes[0].getnewaddress, "", address_type)
            assert_raises_rpc_error(-8, "Only address type 'p2mr' is supported", self.nodes[0].getrawchangeaddress, address_type)

        # Make a wallet to receive coins at
        self.nodes[0].createwallet(wallet_name="desc2", descriptors=True)
        recv_wrpc = self.nodes[0].get_wallet_rpc("desc2")
        send_wrpc = self.nodes[0].get_wallet_rpc("desc1")

        # Generate some coins
        self.generatetoaddress(self.nodes[0], COINBASE_MATURITY + 1, send_wrpc.getnewaddress())

        # Make transactions
        self.log.info("Test sending and receiving")
        addr = recv_wrpc.getnewaddress()
        send_wrpc.sendtoaddress(addr, 10)

        # Make sure things are disabled
        self.log.info("Test disabled RPCs")
        assert_raises_rpc_error(-8, "importprivkey is disabled", recv_wrpc.rpc.importprivkey, "cVpF924EspNh8KjYsfhgY96mmxvT6DgdWiTYMtMjuM74hJaU5psW")
        assert_raises_rpc_error(-8, "importpubkey is disabled", recv_wrpc.rpc.importpubkey, "03789ed0bb717d88f7d321a368d905e7430207ebbd82bd342cf11ae157a7ace5fd")
        assert_raises_rpc_error(-4, "Only legacy wallets are supported by this command", recv_wrpc.rpc.importmulti, [])
        assert_raises_rpc_error(-8, "legacy multisig RPCs are disabled", recv_wrpc.rpc.addmultisigaddress, 1, [recv_wrpc.getnewaddress()])
        assert_raises_rpc_error(-4, "Only legacy wallets are supported by this command", recv_wrpc.rpc.dumpprivkey, recv_wrpc.getnewaddress())
        assert_raises_rpc_error(-4, "Only legacy wallets are supported by this command", recv_wrpc.rpc.dumpwallet, 'wallet.dump')
        assert_raises_rpc_error(-8, "importwallet is disabled", recv_wrpc.rpc.importwallet, 'wallet.dump')
        assert_raises_rpc_error(-4, "Only legacy wallets are supported by this command", recv_wrpc.rpc.sethdseed)

        # Test importaddress
        self.log.info("Test watch-only descriptor wallet")
        self.nodes[0].createwallet(wallet_name="watch-only-desc", disable_private_keys=True, descriptors=True, blank=True)
        wallet_watch_only = self.nodes[0].get_wallet_rpc("watch-only-desc")
        wallet_watch_only.importaddress(addr)
        assert_equal(wallet_watch_only.getaddressinfo(addr)['ismine'], True)
        assert_equal(wallet_watch_only.getaddressinfo(addr)['solvable'], False)
        assert_equal(wallet_watch_only.getbalances()["mine"]['untrusted_pending'], 10)
        self.nodes[0].unloadwallet("watch-only-desc")

        self.log.info("Test encryption")
        # encryptwallet keeps an existing P2MR seed, so the active descriptor stays the same.
        info1 = send_wrpc.getaddressinfo(send_wrpc.getnewaddress())

        # Encrypt wallet 0
        send_wrpc.encryptwallet('pass')
        with WalletUnlock(send_wrpc, "pass"):
            addr = send_wrpc.getnewaddress()
            info2 = send_wrpc.getaddressinfo(addr)
            assert_equal(info1['parent_desc'], info2['parent_desc'])
        send_wrpc.getnewaddress()
        info3 = send_wrpc.getaddressinfo(addr)
        assert_equal(info2['parent_desc'], info3['parent_desc'])

        self.log.info("Test that a locked encrypted wallet hands out its keypool, then needs an unlock")
        # P2MR keys are derived from the private seed, so a locked wallet cannot top up.
        keypool_left = send_wrpc.getwalletinfo()['keypoolsize']
        assert keypool_left > 0
        for _ in range(keypool_left):
            send_wrpc.getnewaddress()
        assert_equal(send_wrpc.getwalletinfo()['keypoolsize'], 0)
        assert_raises_rpc_error(-4, "This wallet has no available keys", send_wrpc.getnewaddress)
        assert_raises_rpc_error(-13, "Please enter the wallet passphrase with walletpassphrase first", send_wrpc.keypoolrefill)
        with WalletUnlock(send_wrpc, "pass"):
            send_wrpc.getnewaddress()
        send_wrpc.getnewaddress()

        self.log.info("Test born encrypted wallets")
        self.nodes[0].createwallet('desc_enc', False, False, 'pass', False, True)
        enc_rpc = self.nodes[0].get_wallet_rpc('desc_enc')
        enc_rpc.getnewaddress() # Makes sure that we can get a new address from a born encrypted wallet

        self.log.info("Test blank descriptor wallets")
        self.nodes[0].createwallet(wallet_name='desc_blank', blank=True, descriptors=True)
        blank_rpc = self.nodes[0].get_wallet_rpc('desc_blank')
        assert_raises_rpc_error(-4, 'This wallet has no available keys', blank_rpc.getnewaddress)

        self.log.info("Test descriptor wallet with disabled private keys")
        self.nodes[0].createwallet(wallet_name='desc_no_priv', disable_private_keys=True, descriptors=True)
        nopriv_rpc = self.nodes[0].get_wallet_rpc('desc_no_priv')
        assert_raises_rpc_error(-4, 'This wallet has no available keys', nopriv_rpc.getnewaddress)

        self.log.info("Test descriptor exports")
        self.nodes[0].createwallet(wallet_name='desc_export', descriptors=True)
        exp_rpc = self.nodes[0].get_wallet_rpc('desc_export')

        public_descs = {}
        for internal in [False, True]:
            int_str = 'internal' if internal else 'external'
            self.log.info("Testing the same P2MR descriptor is returned for {} addresses".format(int_str))
            addr = exp_rpc.getrawchangeaddress() if internal else exp_rpc.getnewaddress()
            desc = exp_rpc.getaddressinfo(addr)['parent_desc']
            assert desc.startswith('mr(pqhd([')
            assert '/87h/1h/0h/{}]/*)'.format(1 if internal else 0) in desc
            for i in range(0, 10):
                addr = exp_rpc.getrawchangeaddress() if internal else exp_rpc.getnewaddress()
                assert_equal(desc, exp_rpc.getaddressinfo(addr)['parent_desc'])
            public_descs[internal] = desc

        # A public mr() descriptor cannot derive PQ keys, so the round trip uses
        # the private export and a blank wallet that holds keys.
        self.log.info("Test that a public P2MR descriptor is refused by a watch-only wallet")
        self.nodes[0].createwallet(wallet_name='desc_import_pub', disable_private_keys=True, descriptors=True)
        imp_pub_rpc = self.nodes[0].get_wallet_rpc('desc_import_pub')
        result = imp_pub_rpc.importdescriptors([{
            'desc': public_descs[True],
            'active': True,
            'timestamp': 'now',
            'internal': True
        }])
        assert_equal(result[0]['success'], False)
        assert 'xpub-only/watch-only imports are unsupported' in result[0]['error']['message']

        self.log.info("Testing import of exported private P2MR descriptors")
        exported = [d for d in exp_rpc.listdescriptors(True)['descriptors'] if d['active']]
        assert_equal(sorted(d['internal'] for d in exported), [False, True])
        self.nodes[0].createwallet(wallet_name='desc_import', blank=True, descriptors=True)
        imp_rpc = self.nodes[0].get_wallet_rpc('desc_import')
        result = imp_rpc.importdescriptors([{
            'desc': d['desc'],
            'active': True,
            'next_index': d['next_index'],
            'timestamp': 'now',
            'internal': d['internal']
        } for d in exported])
        assert_equal([r['success'] for r in result], [True, True])

        for i in range(0, 10):
            assert_equal(exp_rpc.getnewaddress(), imp_rpc.getnewaddress())
            assert_equal(exp_rpc.getrawchangeaddress(), imp_rpc.getrawchangeaddress())

        self.log.info("Test that loading descriptor wallet containing legacy key types throws error")
        self.nodes[0].createwallet(wallet_name="crashme", descriptors=True)
        self.nodes[0].unloadwallet("crashme")
        wallet_db = self.nodes[0].wallets_path / "crashme" / self.wallet_data_filename
        conn = sqlite3.connect(wallet_db)
        with conn:
            # add "cscript" entry: key type is uint160 (20 bytes), value type is CScript (zero-length here)
            conn.execute('INSERT INTO main VALUES(?, ?)', (b'\x07cscript' + b'\x00'*20, b'\x00'))
        conn.close()
        assert_raises_rpc_error(-4, "Unexpected legacy entry in descriptor wallet found.", self.nodes[0].loadwallet, "crashme")

        self.test_concurrent_writes()


if __name__ == '__main__':
    WalletDescriptorTest(__file__).main()
