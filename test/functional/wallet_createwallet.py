#!/usr/bin/env python3
# Copyright (c) 2018-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test createwallet arguments.
"""

from test_framework.address import key_to_p2wpkh
from test_framework.descriptors import descsum_create
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)
from test_framework.wallet_util import generate_keypair, WalletUnlock


EMPTY_PASSPHRASE_MSG = "Empty string given as passphrase, wallet will not be encrypted."
LEGACY_WALLET_MSG = "Wallet created successfully. The legacy wallet type is being deprecated and support for creating and opening legacy wallets will be removed in the future."
# BTX descriptor wallets hold one P2MR pair built like GeneratePQWalletDescriptor (src/wallet/walletutil.cpp):
# mr(pqhd(seed/1h/0h/<change>/*),pk_slh(...)) on test chains, not BIP84 wpkh() descriptors.
P2MR_SEED = "01" * 32


def p2mr_desc(*, internal=False):
    pqhd = f"pqhd({P2MR_SEED}/1h/0h/{1 if internal else 0}/*)"
    return descsum_create(f"mr({pqhd},pk_slh({pqhd}))")


class CreateWalletTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        self.generate(node, 1) # Leave IBD for sethdseed

        self.log.info("Run createwallet with invalid parameters.")
        # Run createwallet with invalid parameters. This must not prevent a new wallet with the same name from being created with the correct parameters.
        assert_raises_rpc_error(-4, "Passphrase provided but private keys are disabled. A passphrase is only used to encrypt private keys, so cannot be used for wallets with private keys disabled.",
            self.nodes[0].createwallet, wallet_name='w0', disable_private_keys=True, passphrase="passphrase")

        self.nodes[0].createwallet(wallet_name='w0')
        w0 = node.get_wallet_rpc('w0')
        address1 = w0.getnewaddress()

        self.log.info("Test disableprivatekeys creation.")
        self.nodes[0].createwallet(wallet_name='w1', disable_private_keys=True)
        w1 = node.get_wallet_rpc('w1')
        assert_raises_rpc_error(-4, "Error: This wallet has no available keys", w1.getnewaddress)
        assert_raises_rpc_error(-4, "Error: This wallet has no available keys", w1.getrawchangeaddress)
        assert_raises_rpc_error(-8, "importpubkey is disabled", w1.rpc.importpubkey, "03789ed0bb717d88f7d321a368d905e7430207ebbd82bd342cf11ae157a7ace5fd")

        self.log.info('Test that private keys cannot be imported')
        privkey, pubkey = generate_keypair(wif=True)
        assert_raises_rpc_error(-8, "importprivkey is disabled", w1.rpc.importprivkey, privkey)
        assert_raises_rpc_error(-4, 'Cannot import private keys to a wallet with private keys disabled', w1.importprivkey, privkey)
        if self.options.descriptors:
            result = w1.importdescriptors([{'desc': descsum_create('wpkh(' + privkey + ')'), 'timestamp': 'now'}])
        else:
            result = w1.importmulti([{'scriptPubKey': {'address': key_to_p2wpkh(pubkey)}, 'timestamp': 'now', 'keys': [privkey]}])
        assert not result[0]['success']
        assert 'warnings' not in result[0]
        assert_equal(result[0]['error']['code'], -4)
        assert_equal(result[0]['error']['message'], 'Cannot import private keys to a wallet with private keys disabled')

        self.log.info("Test blank creation with private keys disabled.")
        self.nodes[0].createwallet(wallet_name='w2', disable_private_keys=True, blank=True)
        w2 = node.get_wallet_rpc('w2')
        assert_raises_rpc_error(-4, "Error: This wallet has no available keys", w2.getnewaddress)
        assert_raises_rpc_error(-4, "Error: This wallet has no available keys", w2.getrawchangeaddress)
        assert_raises_rpc_error(-8, "importpubkey is disabled", w2.rpc.importpubkey, "03789ed0bb717d88f7d321a368d905e7430207ebbd82bd342cf11ae157a7ace5fd")

        self.log.info("Test blank creation with private keys enabled.")
        self.nodes[0].createwallet(wallet_name='w3', disable_private_keys=False, blank=True)
        w3 = node.get_wallet_rpc('w3')
        assert_equal(w3.getwalletinfo()['keypoolsize'], 0)
        assert_raises_rpc_error(-4, "Error: This wallet has no available keys", w3.getnewaddress)
        assert_raises_rpc_error(-4, "Error: This wallet has no available keys", w3.getrawchangeaddress)
        # Raw importprivkey RPC is fail-closed; descriptor wallets map the wrapper to importdescriptors.
        assert_raises_rpc_error(-8, "importprivkey is disabled", w3.rpc.importprivkey, generate_keypair(wif=True)[0])
        if self.options.descriptors:
            w3.importprivkey(generate_keypair(wif=True)[0])
        # Imported private keys are currently ignored by the keypool
        assert_equal(w3.getwalletinfo()['keypoolsize'], 0)
        assert_raises_rpc_error(-4, "Error: This wallet has no available keys", w3.getnewaddress)
        # Set the seed
        if self.options.descriptors:
            w3.importdescriptors([{
                'desc': p2mr_desc(),
                'timestamp': 'now',
                'active': True
            },
            {
                'desc': p2mr_desc(internal=True),
                'timestamp': 'now',
                'active': True,
                'internal': True
            }])
        else:
            w3.sethdseed()
        assert_equal(w3.getwalletinfo()['keypoolsize'], 1)
        w3.getnewaddress()
        w3.getrawchangeaddress()

        self.log.info("Test blank creation with privkeys enabled and then encryption")
        self.nodes[0].createwallet(wallet_name='w4', disable_private_keys=False, blank=True)
        w4 = node.get_wallet_rpc('w4')
        assert_equal(w4.getwalletinfo()['keypoolsize'], 0)
        assert_raises_rpc_error(-4, "Error: This wallet has no available keys", w4.getnewaddress)
        assert_raises_rpc_error(-4, "Error: This wallet has no available keys", w4.getrawchangeaddress)
        # Encrypt the wallet. Nothing should change about the keypool
        w4.encryptwallet('pass')
        assert_raises_rpc_error(-4, "Error: This wallet has no available keys", w4.getnewaddress)
        assert_raises_rpc_error(-4, "Error: This wallet has no available keys", w4.getrawchangeaddress)
        with WalletUnlock(w4, "pass"):
            # Now set a seed and it should work. Wallet should also be encrypted
            if self.options.descriptors:
                w4.importdescriptors([{
                    'desc': p2mr_desc(),
                    'timestamp': 'now',
                    'active': True
                },
                {
                    'desc': p2mr_desc(internal=True),
                    'timestamp': 'now',
                    'active': True,
                    'internal': True
                }])
            else:
                w4.sethdseed()
            w4.getnewaddress()
            w4.getrawchangeaddress()

        self.log.info("Test blank creation with privkeys disabled and then encryption")
        self.nodes[0].createwallet(wallet_name='w5', disable_private_keys=True, blank=True)
        w5 = node.get_wallet_rpc('w5')
        assert_equal(w5.getwalletinfo()['keypoolsize'], 0)
        assert_raises_rpc_error(-4, "Error: This wallet has no available keys", w5.getnewaddress)
        assert_raises_rpc_error(-4, "Error: This wallet has no available keys", w5.getrawchangeaddress)
        # Encrypt the wallet
        assert_raises_rpc_error(-16, "Error: wallet does not contain private keys, nothing to encrypt.", w5.encryptwallet, 'pass')
        assert_raises_rpc_error(-4, "Error: This wallet has no available keys", w5.getnewaddress)
        assert_raises_rpc_error(-4, "Error: This wallet has no available keys", w5.getrawchangeaddress)

        self.log.info('New blank and encrypted wallets can be created')
        self.nodes[0].createwallet(wallet_name='wblank', disable_private_keys=False, blank=True, passphrase='thisisapassphrase')
        wblank = node.get_wallet_rpc('wblank')
        assert_raises_rpc_error(-13, "Error: Please enter the wallet passphrase with walletpassphrase first.", wblank.signmessage, "needanargument", "test")
        with WalletUnlock(wblank, "thisisapassphrase"):
            assert_raises_rpc_error(-4, "Error: This wallet has no available keys", wblank.getnewaddress)
            assert_raises_rpc_error(-4, "Error: This wallet has no available keys", wblank.getrawchangeaddress)

        self.log.info('Test creating a new encrypted wallet.')
        # Born encrypted wallet is created (has keys)
        self.nodes[0].createwallet(wallet_name='w6', disable_private_keys=False, blank=False, passphrase='thisisapassphrase')
        w6 = node.get_wallet_rpc('w6')
        assert_raises_rpc_error(-13, "Error: Please enter the wallet passphrase with walletpassphrase first.", w6.signmessage, "needanargument", "test")
        with WalletUnlock(w6, "thisisapassphrase"):
            w6.signmessage(w6.getnewaddress('', 'p2mr'), "test")
            w6.keypoolrefill(1)
            # One key per active descriptor: BTX has a single P2MR pair (Bitcoin: one per output type)
            walletinfo = w6.getwalletinfo()
            keys = 1
            assert_equal(walletinfo['keypoolsize'], keys)
            assert_equal(walletinfo['keypoolsize_hd_internal'], keys)
        # Allow empty passphrase, but there should be a warning
        resp = self.nodes[0].createwallet(wallet_name='w7', disable_private_keys=False, blank=False, passphrase='')
        assert_equal(resp["warnings"], [EMPTY_PASSPHRASE_MSG])

        w7 = node.get_wallet_rpc('w7')
        assert_raises_rpc_error(-15, 'Error: running with an unencrypted wallet, but walletpassphrase was called.', w7.walletpassphrase, '', 60)

        self.log.info('Test making a wallet with avoid reuse flag')
        self.nodes[0].createwallet('w8', False, False, '', True) # Use positional arguments to check for bug where avoid_reuse could not be set for wallets without needing them to be encrypted
        w8 = node.get_wallet_rpc('w8')
        assert_raises_rpc_error(-15, 'Error: running with an unencrypted wallet, but walletpassphrase was called.', w7.walletpassphrase, '', 60)
        assert_equal(w8.getwalletinfo()["avoid_reuse"], True)

        self.log.info('Using a passphrase with private keys disabled returns error')
        assert_raises_rpc_error(-4, 'Passphrase provided but private keys are disabled. A passphrase is only used to encrypt private keys, so cannot be used for wallets with private keys disabled.', self.nodes[0].createwallet, wallet_name='w9', disable_private_keys=True, passphrase='thisisapassphrase')

        if not self.options.descriptors:
            self.log.info("Test legacy wallet deprecation")
            result = self.nodes[0].createwallet(wallet_name="legacy_w0", descriptors=False, passphrase=None)
            assert_equal(result, {
                "name": "legacy_w0",
                "warnings": [LEGACY_WALLET_MSG],
            })
            result = self.nodes[0].createwallet(wallet_name="legacy_w1", descriptors=False, passphrase="")
            assert_equal(result, {
                "name": "legacy_w1",
                "warnings": [EMPTY_PASSPHRASE_MSG, LEGACY_WALLET_MSG],
            })

        self.log.info("Check that the version number is being logged correctly")
        with node.assert_debug_log(expected_msgs=[], unexpected_msgs=["Last client version = ", "Wallet file version = "]):
            node.createwallet("version_check")
        wallet = node.get_wallet_rpc("version_check")
        wallet_version = wallet.getwalletinfo()["walletversion"]
        client_version = node.getnetworkinfo()["version"]
        wallet.unloadwallet()
        with node.assert_debug_log(
            expected_msgs=[f"Last client version = {client_version}", f"Wallet file version = {wallet_version}"],
            unexpected_msgs=["Wallet file version = 10500"]
        ):
            node.loadwallet("version_check")


if __name__ == '__main__':
    CreateWalletTest(__file__).main()
