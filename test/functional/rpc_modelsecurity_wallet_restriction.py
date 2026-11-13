#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""modelsecurity is an owner RPC: it refuses -rpcauth wallet-restricted users.

modelsecurity dispatches requests to the node-owned model-security guard.
{"op": "pause"} needs no signed record, while resuming needs an owner-signed
resume record. An -rpcauth user restricted to one wallet, or to none ("-"),
could therefore pause the guard for the whole node. Like stop, the RPC must
refuse such a user, and must still work for an unrestricted user.
"""

import hmac
import http.client
import json
import os
import urllib.parse

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, str_to_b64str

USERS = {
    # name: (password, wallet restriction)
    "only_wa": ("pw-only-wa", "wa"),
    "no_wallet": ("pw-no-wallet", "-"),
}
REFUSED = "Method not available for wallet-restricted RPC users"


def rpcauth_line(user, password, restriction):
    salt = os.urandom(16).hex()
    digest = hmac.new(salt.encode(), password.encode(), "SHA256").hexdigest()
    return f"-rpcauth={user}:{salt}${digest}:{restriction}"


class ModelSecurityWalletRestrictionTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        # Keep the product default for -modelnet so the guard runs, as in
        # feature_model_security_v2.py.
        self.extra_args = [[rpcauth_line(u, pw, r) for u, (pw, r) in USERS.items()]]

    def call_as(self, user, method, params):
        url = urllib.parse.urlparse(self.nodes[0].url)
        headers = {"Authorization": "Basic " + str_to_b64str(f"{user}:{USERS[user][0]}")}
        conn = http.client.HTTPConnection(url.hostname, url.port, timeout=120)
        body = json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": params})
        conn.request("POST", "/", body, headers)
        out = json.loads(conn.getresponse().read())
        conn.close()
        return out

    def run_test(self):
        node = self.nodes[0]

        def ready():
            try:
                return node.modelsecurity({"op": "status"}).get("ok") is True
            except Exception:
                return False

        self.wait_until(ready, timeout=120)
        assert_equal(node.modelsecurity({"op": "status"})["paused"], False)

        self.log.info("A wallet-restricted user cannot reach the guard")
        for user in USERS:
            for request in ({"op": "status"}, {"op": "pause"}):
                out = self.call_as(user, "modelsecurity", [request])
                assert out["error"] is not None, f"{user} {request['op']} answered: {out['result']}"
                assert_equal(out["error"]["message"], REFUSED)
        assert_equal(node.modelsecurity({"op": "status"})["paused"], False)

        self.log.info("An unrestricted user still can")
        assert_equal(node.modelsecurity({"op": "pause"})["ok"], True)
        assert_equal(node.modelsecurity({"op": "status"})["paused"], True)


if __name__ == "__main__":
    ModelSecurityWalletRestrictionTest(__file__).main()
