#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""preparebountyclaim and signbountyclaim must check wallet access first.

Both read a local secret_ref file. Their errors tell a missing file, a file of
the wrong size and a file of the wrong format apart. An -rpcauth user
restricted to no wallet ("-") must get the wallet error for every path, so the
calls cannot be used to probe which files exist on the node.
"""

import hmac
import http.client
import json
import os
import urllib.parse

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, str_to_b64str

MATMUL_OFF = [
    "-regtestmatmulbindingheight=2147483647",
    "-regtestmatmulproductdigestheight=2147483647",
    "-regtestmatmulv4height=2147483647",
    "-regtestmatmulrequireproductpayload=0",
]
USER, PASSWORD = "no_wallet", "pw-no-wallet"


def rpcauth_line(user, password, restriction):
    salt = os.urandom(16).hex()
    digest = hmac.new(salt.encode(), password.encode(), "SHA256").hexdigest()
    return f"-rpcauth={user}:{salt}${digest}:{restriction}"


class BountySecretRefWalletRestrictionTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-nomodelnet", "-modellandiscovery=0", *MATMUL_OFF, rpcauth_line(USER, PASSWORD, "-")]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def call_as_restricted(self, method, params):
        url = urllib.parse.urlparse(self.nodes[0].url)
        headers = {"Authorization": "Basic " + str_to_b64str(f"{USER}:{PASSWORD}")}
        conn = http.client.HTTPConnection(url.hostname, url.port, timeout=60)
        conn.request("POST", "/", json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": params}), headers)
        out = json.loads(conn.getresponse().read())
        conn.close()
        return out["error"]

    def run_test(self):
        node = self.nodes[0]
        node.createwallet("w")
        files = {
            "missing": os.path.join(self.options.tmpdir, "no-such-file"),
            "directory": self.options.tmpdir,
            "empty": os.path.join(self.options.tmpdir, "empty"),
            "large": os.path.join(self.options.tmpdir, "large"),
            "wrong-format": os.path.join(self.options.tmpdir, "wrong-format"),
            "preimage": os.path.join(self.options.tmpdir, "preimage"),
        }
        with open(files["empty"], "wb"):
            pass
        with open(files["large"], "wb") as f:
            f.write(b"x" * 200)
        with open(files["wrong-format"], "wb") as f:
            f.write(b"y" * 20)
        with open(files["preimage"], "wb") as f:
            f.write(b"\x01" * 32)
        plan = {"outpoint": "11" * 32 + ":0", "destination": "unused"}
        for method in ("preparebountyclaim", "signbountyclaim"):
            for kind, path in files.items():
                error = self.call_as_restricted(method, [{**plan, "secret_ref": path}])
                self.log.info(f"{method} {kind}: {error}")
                assert_equal(error["code"], -18)
                assert "No wallet is loaded" in error["message"], error


if __name__ == "__main__":
    BountySecretRefWalletRestrictionTest(__file__).main()
