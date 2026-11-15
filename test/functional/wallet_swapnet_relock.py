#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""SwapNet re-locks the reserved funding inputs it still holds after a restart.

A prepared swap funding records its wallet inputs in the coinlocks table of
swapnet/state.sqlite, and the startup path locks them again with
lockunspent. Once that funding is broadcast its inputs are spent, and the
rows stay until the swap reaches a terminal stage.

0.34.16 locked nothing after a restart in that window and reported a
startup error for the native asset: the host ran the re-lock while btxd's
RPC server was still in warmup, and lockunspent refuses the whole call when
one output is spent.

The test writes the two rows such a restart sees, one input already spent and
one not, then restarts the node. The unspent input must be locked and the
native asset must have no startup error.
"""

import sqlite3

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

SWAPNET_ARGS = [
    "-swapnet=1",
    "-modelbind=off",
    "-autoshieldcoinbase=0",
    "-regtestmatmulbindingheight=2147483647",
    "-regtestmatmulproductdigestheight=2147483647",
    "-regtestmatmulv4height=2147483647",
    "-regtestmatmulrequireproductpayload=0",
]


class SwapNetRelockTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.wallet_names = []
        self.extra_args = [SWAPNET_ARGS]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        node.createwallet(wallet_name="w", load_on_startup=True)
        wallet = node.get_wallet_rpc("w")
        address = wallet.getnewaddress(address_type="p2mr")
        self.generatetoaddress(node, 110, address)
        asset = f"btx:{node.getblockhash(0)}:0:native"
        assert asset not in node.getswapwalletinfo()["startup_errors"]

        coins = sorted(wallet.listunspent(), key=lambda c: (c["txid"], c["vout"]))
        spent, kept = coins[0], coins[1]
        self.log.info("Spend one input, as a broadcast swap funding does")
        psbt = wallet.walletcreatefundedpsbt(
            [{"txid": spent["txid"], "vout": spent["vout"]}],
            [{wallet.getnewaddress(address_type="p2mr"): 1}], 0, {"add_inputs": False})["psbt"]
        signed = wallet.walletprocesspsbt(psbt)
        node.sendrawtransaction(node.finalizepsbt(signed["psbt"])["hex"])
        self.generatetoaddress(node, 1, address)

        self.log.info("Record both inputs as reserved by an unfinished swap, then restart")
        self.stop_node(0)
        db = sqlite3.connect(node.chain_path / "swapnet" / "state.sqlite")
        with db:
            for coin in (spent, kept):
                db.execute("INSERT INTO coinlocks VALUES(?,?,?)",
                           (asset, f"{coin['txid']}:{coin['vout']}", "ab" * 32))
        db.close()
        self.start_node(0, SWAPNET_ARGS)
        wallet = node.get_wallet_rpc("w")

        # The worker re-locks on its first ticks, once btxd answers RPC. Only
        # the native asset's entry counts: an operator's own Bitcoin node may
        # add one.
        def kept_input_relocked():
            errors = node.getswapwalletinfo()["startup_errors"]
            return asset not in errors and wallet.listlockunspent() == [{"txid": kept["txid"], "vout": kept["vout"]}]
        self.wait_until(kept_input_relocked, timeout=10)
        assert_equal(node.getswapwalletinfo()["native_wallet"], "w")


if __name__ == "__main__":
    SwapNetRelockTest(__file__).main()
