#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""SwapNet takes its principal and owner role from the authenticated RPC connection.

Pins the rules in doc/swapnet/SPECIFICATION.md ("The native RPC layer derives
Principal and owner status from the authenticated JSONRPCRequest"):

1. The local cookie is an owner, with principal "owner:cookie".
2. A named RPC user is "rpc:<username>", and is an owner only when listed in
   -swapnetowner.
3. An empty HTTP user and the name "local-owner" are rejected. An HTTP Basic
   user name ends at the first colon, so a client cannot send a user name that
   starts with "owner:"; sending "owner:cookie" authenticates the user "owner",
   who gets "rpc:owner" and no owner role.
4. A wallet restriction must match the wallet named by the call, and that user
   is never an owner, even when listed in -swapnetowner.

Owner-scope methods check the role before they read their named fields, so an
empty request object returns OWNER_REQUIRED to a non-owner and PARAMS to an
owner, with no side effect. Mandates are listed only to their exact principal,
which shows the principal string each caller gets.

The local Qt console (no HTTP user and no peer address) is the other owner
context. It is not reachable from a functional test.
"""

import hmac
import http.client
import json
import os
import time
import urllib.parse

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error, str_to_b64str

RPC_MISC_ERROR = -1
RPC_INVALID_PARAMETER = -8
RPC_WALLET_NOT_FOUND = -18

# name: (password, wallet restriction or None for an unrestricted user)
USERS = {
    "alice": ("pw-alice", None),       # listed in -swapnetowner
    "erin": ("pw-erin", None),         # not listed
    "": ("pw-empty", None),            # empty HTTP user
    "local-owner": ("pw-local", None),
    "owner": ("cookie:pw-owner", None),  # what a client sending "owner:cookie:..." authenticates as
    "carol": ("pw-carol", "w1"),       # restricted to w1 and listed in -swapnetowner
    "dave": ("pw-dave", "-"),          # restricted to no wallet
}
SWAPNET_OWNERS = ["alice", "carol"]

# Owner-scope methods that need a named field, so an owner's empty request
# fails on its arguments and changes nothing.
OWNER_PROBES = ["createswapmandate", "revokeswapmandate", "setswapmarket",
                "setswapassetpolicy", "exportswaprecovery"]
OWNER_REQUIRED = "OWNER_REQUIRED"
RESERVED = "Reserved SwapNet principal"
RESTRICTED = "Wallet restriction does not allow this SwapNet wallet"


def rpcauth_line(user, password, restriction):
    salt = os.urandom(16).hex()
    digest = hmac.new(salt.encode(), password.encode(), "SHA256").hexdigest()
    line = f"-rpcauth={user}:{salt}${digest}"
    return line if restriction is None else f"{line}:{restriction}"


class SwapNetPrincipalTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        # The wallets are created with SwapNet off and loaded at startup, so the test
        # does not depend on createwallet while SwapNet runs.
        self.wallet_names = []
        self.extra_args = [["-modelbind=off"]]
        self.swapnet_args = (["-modelbind=off", "-swapnet=1"]
                             + [f"-swapnetowner={u}" for u in SWAPNET_OWNERS]
                             + [rpcauth_line(u, pw, r) for u, (pw, r) in USERS.items()])

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def call_as(self, user, method, params=None, uripath="/"):
        url = urllib.parse.urlparse(self.nodes[0].url)
        headers = {"Authorization": "Basic " + str_to_b64str(f"{user}:{USERS[user][0]}")}
        conn = http.client.HTTPConnection(url.hostname, url.port, timeout=120)
        body = json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": [params or {}]})
        conn.request("POST", uripath, body, headers)
        resp = conn.getresponse()
        assert resp.status != 401, f"{user!r} was not authenticated"
        out = json.loads(resp.read())
        conn.close()
        return out

    def assert_ok(self, user, method, params=None, uripath="/"):
        out = self.call_as(user, method, params, uripath)
        assert out["error"] is None, f"{user!r} {method}: {out['error']}"
        return out["result"]

    def assert_error(self, code, message, user, method, params=None, uripath="/"):
        err = self.call_as(user, method, params, uripath)["error"]
        assert err is not None, f"{user!r} {method}: expected error {code} {message!r}"
        assert_equal(err["code"], code)
        assert message in err["message"], f"{user!r} {method}: {err['message']!r} lacks {message!r}"

    def mandate(self, principal):
        return {"principal": principal, "asset": self.btx_asset, "max_total_atoms": "1000",
                "max_trade_atoms": "100", "max_fee_atoms": "10",
                "expires_at": int(time.time()) + 86400, "nonce": os.urandom(32).hex()}

    def run_test(self):
        node = self.nodes[0]
        assert_equal(node.getblockchaininfo()["chain"], "regtest")
        for name in ["w1", "w2"]:
            node.createwallet(wallet_name=name, load_on_startup=True)
        self.restart_node(0, self.swapnet_args)
        assert_equal(sorted(node.listwallets()), ["w1", "w2"])
        self.btx_asset = f"btx:{node.getblockhash(0)}:0:native"

        scopes = {m["name"]: m["scope"] for m in node.getswapcapabilities()["methods"]}
        for method in OWNER_PROBES:
            assert_equal(scopes[method], "owner")
        owner_only = sorted(m for m, s in scopes.items() if s in ("owner", "maker"))

        self.log.info("Rule 1: the cookie is an owner with principal owner:cookie")
        for method in OWNER_PROBES:
            assert_raises_rpc_error(RPC_MISC_ERROR, "PARAMS", getattr(node, method), {})
        ids = {}
        for principal in ["owner:cookie", "rpc:alice", "rpc:erin", "rpc:owner", "rpc:carol"]:
            ids[principal] = node.createswapmandate({"mandate": self.mandate(principal)})["mandate_id"]
        assert_equal([m["id"] for m in node.listswapmandates()["mandates"]], [ids["owner:cookie"]])

        self.log.info("Rule 2: rpc:<user>, an owner only when listed in -swapnetowner")
        for method in OWNER_PROBES:
            self.assert_error(RPC_MISC_ERROR, "PARAMS", "alice", method)
        for method in owner_only:
            self.assert_error(RPC_MISC_ERROR, OWNER_REQUIRED, "erin", method)
        for user in ["alice", "erin"]:
            mandates = self.assert_ok(user, "listswapmandates")["mandates"]
            assert_equal([m["id"] for m in mandates], [ids[f"rpc:{user}"]])
            assert_equal(mandates[0]["mandate"]["principal"], f"rpc:{user}")
        assert_equal(self.assert_ok("erin", "getswapnetworkinfo")["protocol"], 2)

        self.log.info("Rule 3: an empty user and local-owner are rejected; owner:cookie is not claimable")
        for user in ["", "local-owner"]:
            self.assert_error(RPC_INVALID_PARAMETER, RESERVED, user, "getswapnetworkinfo")
            self.assert_error(RPC_INVALID_PARAMETER, RESERVED, user, "createswapmandate")
        mandates = self.assert_ok("owner", "listswapmandates")["mandates"]
        assert_equal([m["id"] for m in mandates], [ids["rpc:owner"]])
        for method in owner_only:
            self.assert_error(RPC_MISC_ERROR, OWNER_REQUIRED, "owner", method)

        self.log.info("Rule 4: a wallet restriction names the wallet and is never an owner")
        # Only an owner may bind the SwapNet wallet.
        self.assert_error(RPC_MISC_ERROR, OWNER_REQUIRED, "carol", "getswapnetworkinfo")
        node.get_wallet_rpc("w1").getswapnetworkinfo()
        assert_equal(self.assert_ok("carol", "getswapnetworkinfo")["protocol"], 2)
        assert_equal(self.assert_ok("carol", "getswapnetworkinfo", uripath="/wallet/w1")["protocol"], 2)
        self.assert_error(RPC_WALLET_NOT_FOUND, RESTRICTED, "carol", "getswapnetworkinfo", uripath="/wallet/w2")
        for method in owner_only:
            self.assert_error(RPC_MISC_ERROR, OWNER_REQUIRED, "carol", method)
        mandates = self.assert_ok("carol", "listswapmandates")["mandates"]
        assert_equal([m["id"] for m in mandates], [ids["rpc:carol"]])
        for uripath in ["/", "/wallet/w1"]:
            self.assert_error(RPC_WALLET_NOT_FOUND, RESTRICTED, "dave", "getswapnetworkinfo", uripath=uripath)

        self.log.info("JSON fields cannot change the role")
        self.assert_error(RPC_MISC_ERROR, OWNER_REQUIRED, "erin", "exportswaprecovery",
                          {"passphrase": "x", "owner": True, "principal": "owner:cookie"})
        assert_equal(len(node.listswapmandates()["mandates"]), 1)


if __name__ == "__main__":
    SwapNetPrincipalTest(__file__).main()
