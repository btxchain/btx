#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Wallet RPCs that read or write a server-side file refuse wallet-restricted users.

restorewalletbundle, backupwalletbundle and backupwallet already call
EnsureNotWalletRestricted. importwalletbundle, exportwalletbundle,
importlabels and exportlabels did not: an -rpcauth user restricted to wallet
"wa" could import another wallet's .btxwallet file from the server into "wa"
and spend that wallet's coins, and could write files to any server path.
Each of them must refuse such a user before it touches the file, and must
still work for an unrestricted user.
"""

import hmac
import http.client
import json
import os
import urllib.parse

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, str_to_b64str

USER, PASSWORD, RESTRICTION = "only_wa", "pw-only-wa", "wa"
REFUSED = "Method not available for wallet-restricted RPC users"


def rpcauth_line(user, password, restriction):
    salt = os.urandom(16).hex()
    digest = hmac.new(salt.encode(), password.encode(), "SHA256").hexdigest()
    return f"-rpcauth={user}:{salt}${digest}:{restriction}"


class WalletFileRpcRestrictionTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[
            "-autoshieldcoinbase=0",
            "-modelnet=0",
            "-modelbind=off",
            "-regtestmatmulbindingheight=2147483647",
            "-regtestmatmulproductdigestheight=2147483647",
            "-regtestmatmulv4height=2147483647",
            "-regtestmatmulrequireproductpayload=0",
            rpcauth_line(USER, PASSWORD, RESTRICTION),
        ]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def call_as_restricted(self, method, params):
        url = urllib.parse.urlparse(self.nodes[0].url)
        headers = {"Authorization": "Basic " + str_to_b64str(f"{USER}:{PASSWORD}")}
        conn = http.client.HTTPConnection(url.hostname, url.port, timeout=120)
        body = json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": params})
        conn.request("POST", f"/wallet/{RESTRICTION}", body, headers)
        out = json.loads(conn.getresponse().read())
        conn.close()
        return out

    def run_test(self):
        node = self.nodes[0]
        tmp = self.options.tmpdir
        node.createwallet(wallet_name="victim", descriptors=True)
        victim = node.get_wallet_rpc("victim")
        node.createwallet(wallet_name=RESTRICTION, descriptors=True)
        wa = node.get_wallet_rpc(RESTRICTION)
        node.createwallet(wallet_name="miner", descriptors=True)
        miner = node.get_wallet_rpc("miner")
        self.generatetoaddress(node, 101, miner.getnewaddress(), sync_fun=self.no_op)
        victim_addr = victim.getnewaddress()
        miner.sendtoaddress(victim_addr, 7)
        self.generatetoaddress(node, 1, miner.getnewaddress(), sync_fun=self.no_op)

        self.log.info("The operator exports the victim wallet's bundle and labels on the server")
        bundle = os.path.join(tmp, "victim.btxwallet.json")
        labels = os.path.join(tmp, "victim.labels.jsonl")
        victim.exportwalletbundle(bundle, None, 1)
        victim.setlabel(victim_addr, "victim savings")
        victim.exportlabels(labels)

        self.log.info("A user restricted to wallet wa is refused by every file RPC")
        out_bundle = os.path.join(tmp, "wa.btxwallet.json")
        out_labels = os.path.join(tmp, "wa.labels.jsonl")
        for method, params in [
            ("importwalletbundle", [bundle, True]),
            ("exportwalletbundle", [out_bundle, None, 1]),
            ("importlabels", [labels]),
            ("exportlabels", [out_labels]),
            # Already refused before this change, for comparison.
            ("backupwallet", [os.path.join(tmp, "wa.dat")]),
        ]:
            out = self.call_as_restricted(method, params)
            assert out["error"] is not None, f"{method} answered a wallet-restricted user: {out['result']}"
            assert_equal(out["error"]["message"], REFUSED)
        assert not os.path.exists(out_bundle)
        assert not os.path.exists(out_labels)
        assert_equal(wa.getaddressinfo(victim_addr)["ismine"], False)
        assert_equal(wa.getbalance(), 0)
        assert_equal(wa.listlabels(), [])

        self.log.info("An unrestricted user can still use them")
        assert wa.exportwalletbundle(out_bundle, None, 1)["success"]
        assert_equal(wa.exportlabels(out_labels)["labels"], 0)
        assert_equal(wa.importlabels(labels)["imported"], 1)


if __name__ == "__main__":
    WalletFileRpcRestrictionTest(__file__).main()
