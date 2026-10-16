#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Test that a PQ key lookup on a locked wallet does not stop it signing after unlock.

walletprocesspsbt with sign=false does not ask for the passphrase, but for an
input that carries another party's PQ pubkey it still looks up private keys.

A wallet loaded while locked has no private keys in memory, PQ seeds
included, so that lookup gets a signing provider without private keys. That
provider must not be returned once the wallet is unlocked: otherwise, after
walletpassphrase, the wallet cannot sign for any of its coins until it is
reloaded.

The wallet is encrypted, is reloaded while locked (so its caches start empty)
and holds one coin on a receive address and one on a change address.
"""
from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

PASSPHRASE = "passphrase"
COIN_AMOUNT = Decimal("2")


class WalletP2MRLockedKeyLookupTest(BitcoinTestFramework):
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

    def mine(self, n=1):
        self.generatetoaddress(self.nodes[0], n, self.burn_addr, sync_fun=self.no_op)

    def run_test(self):
        node = self.nodes[0]
        node.createwallet(wallet_name="funder", descriptors=True)
        funder = node.get_wallet_rpc("funder")
        node.createwallet(wallet_name="burn", descriptors=True)
        self.burn_addr = node.get_wallet_rpc("burn").getnewaddress()
        for _ in range(10):
            self.generatetoaddress(node, 1, funder.getnewaddress(), sync_fun=self.no_op)
        self.mine(100)

        # An encrypted wallet. Its first receive address is never funded; the
        # coins sit on the second receive address and on a change address.
        node.createwallet(wallet_name="locked", descriptors=True, passphrase=PASSPHRASE)
        wallet = node.get_wallet_rpc("locked")
        wallet.walletpassphrase(PASSPHRASE, 600)
        wallet.getnewaddress()
        outputs = {
            wallet.getnewaddress(): COIN_AMOUNT,
            wallet.getrawchangeaddress(): COIN_AMOUNT,
        }
        wallet.walletlock()

        # An input of another wallet, signed but not finalized.
        node.createwallet(wallet_name="party", descriptors=True)
        party = node.get_wallet_rpc("party")
        outputs[party.getnewaddress()] = COIN_AMOUNT
        funder.sendmany("", outputs)
        self.mine()
        psbt = party.walletcreatefundedpsbt(inputs=[], outputs=[{self.burn_addr: 1}])["psbt"]
        processed = party.walletprocesspsbt(psbt=psbt, sign=True, finalize=False)
        assert_equal(processed["complete"], False)
        party_psbt = processed["psbt"]
        assert "p2mr_partial_signatures" in node.decodepsbt(party_psbt)["inputs"][0]

        self.log.info("Reload the wallet while locked, then process another party's PSBT with sign=false")
        node.unloadwallet("locked")
        node.loadwallet("locked")
        wallet = node.get_wallet_rpc("locked")
        assert_equal(wallet.getwalletinfo()["unlocked_until"], 0)
        # Allowed while locked: no signing is requested.
        wallet.walletprocesspsbt(psbt=party_psbt, sign=False)

        self.log.info("After walletpassphrase the wallet can still sign both coins")
        wallet.walletpassphrase(PASSPHRASE, 600)
        utxos = wallet.listunspent()
        assert_equal(len(utxos), 2)
        raw = wallet.createrawtransaction(
            [{"txid": u["txid"], "vout": u["vout"]} for u in utxos],
            [{self.burn_addr: 2 * COIN_AMOUNT - Decimal("0.1")}])
        signed = wallet.signrawtransactionwithwallet(raw)
        assert signed["complete"], signed.get("errors")
        assert node.testmempoolaccept([signed["hex"]])[0]["allowed"]

        # An ordinary send that needs both coins.
        txid = wallet.sendtoaddress(self.burn_addr, COIN_AMOUNT + Decimal("1"))
        assert txid in node.getrawmempool()


if __name__ == "__main__":
    WalletP2MRLockedKeyLookupTest(__file__).main()
