#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Model feed RPCs must respect the -rpcauth wallet restriction.

The feed RPCs (getmodelreleaseeconomics, getfundablemodels, ...) join each
release card against wallet state. An -rpcauth user restricted to one wallet,
or to no wallet ("-"), must not see state from other wallets through that join.

A stub helper on -modelrpcsocket serves one card whose output_script pays an
address of wallet "wb". Only wallet state can mark that card as funded.
"""

import json
import os
import shutil
import socket
import tempfile
import threading
import urllib.parse
import http.client
import hmac

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, str_to_b64str

MATMUL_OFF = [
    "-regtestmatmulbindingheight=2147483647",
    "-regtestmatmulproductdigestheight=2147483647",
    "-regtestmatmulv4height=2147483647",
    "-regtestmatmulrequireproductpayload=0",
]
RELEASE_ID = "ab" * 48
FEED_METHODS = {
    "getmodeleconomyentry", "getmodelreleaseeconomics", "getmodelfeed", "getrecentreleases",
    "getfundablemodels", "getrecentlyunlockedmodels", "getreleasefeed",
}
USERS = {
    # name: (password, wallet restriction)
    "only_wa": ("pw-only-wa", "wa"),
    "no_wallet": ("pw-no-wallet", "-"),
}


def rpcauth_line(user, password, restriction):
    salt = os.urandom(16).hex()
    digest = hmac.new(salt.encode(), password.encode(), "SHA256").hexdigest()
    return f"-rpcauth={user}:{salt}${digest}:{restriction}"


class StubHelper(threading.Thread):
    """Answers the btxd -> helper unix RPC with one fixed card."""

    def __init__(self, path):
        super().__init__(daemon=True)
        self.path = path
        self.output_script = ""
        self.ingested = []
        self.stop_event = threading.Event()
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.bind(path)
        self.sock.listen(16)
        self.sock.settimeout(0.2)

    def card(self):
        return {"release_id": RELEASE_ID, "output_script": self.output_script, "target_atoms": 100 * 10**8}

    def reply(self, method, params):
        if method == "ingestchainfundingobservation":
            self.ingested.append(params[0] if params else None)
            return {"accepted": True}
        if method in FEED_METHODS:
            if method in ("getmodeleconomyentry", "getmodelreleaseeconomics"):
                return self.card()
            return {"results": [self.card()]}
        return {}

    def run(self):
        while not self.stop_event.is_set():
            try:
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue
            with conn:
                conn.settimeout(5)
                buf = b""
                try:
                    while b"\n" not in buf:
                        data = conn.recv(65536)
                        if not data:
                            break
                        buf += data
                    req = json.loads(buf.decode())
                    result = self.reply(req.get("method"), req.get("params") or [])
                    conn.sendall((json.dumps({"result": result, "error": None, "id": req.get("id")}) + "\n").encode())
                except (OSError, ValueError):
                    continue

    def stop(self):
        self.stop_event.set()
        self.join(5)
        self.sock.close()


class ModelnetWalletRestrictionTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.helper = None
        self.sock_dir = None

    def skip_test_if_missing_module(self):
        self.skip_if_platform_not_posix()
        self.skip_if_no_wallet()

    def setup_nodes(self):
        # A unix socket path must fit in sun_path (104 bytes on macOS), and the
        # test_runner tmpdir can be longer than that.
        self.sock_dir = tempfile.mkdtemp(prefix="btxmr-")
        self.helper_path = os.path.join(self.sock_dir, "h.sock")
        self.helper = StubHelper(self.helper_path)
        self.helper.start()
        args = [
            "-modelnet=1",
            "-modelbind=off",
            f"-modelrpcsocket={self.helper_path}",
            f"-modeld={os.path.join(self.options.tmpdir, 'no-such-modeld')}",
            *MATMUL_OFF,
        ]
        args += [rpcauth_line(u, pw, r) for u, (pw, r) in USERS.items()]
        self.add_nodes(1, extra_args=[args])
        self.start_nodes()

    def shutdown(self):
        if self.helper is not None:
            self.helper.stop()
        exit_code = super().shutdown()
        if self.sock_dir is not None:
            shutil.rmtree(self.sock_dir, ignore_errors=True)
        return exit_code

    def call_as(self, user, method, params=None, uripath="/"):
        node = self.nodes[0]
        url = urllib.parse.urlparse(node.url)
        headers = {"Authorization": "Basic " + str_to_b64str(f"{user}:{USERS[user][0]}")}
        conn = http.client.HTTPConnection(url.hostname, url.port, timeout=60)
        body = json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": params or []})
        conn.request("POST", uripath, body, headers)
        resp = conn.getresponse()
        out = json.loads(resp.read())
        conn.close()
        return resp.status, out

    def wallet_view(self, user, method):
        """Return the wallet-derived fields of the stub card as seen by user."""
        params = [RELEASE_ID] if method == "getmodelreleaseeconomics" else [{"limit": 10}]
        if user is None:
            res = getattr(self.nodes[0], method)(*params)
        else:
            status, out = self.call_as(user, method, params)
            assert_equal(status, 200)
            res = out["result"]
        card = res if method == "getmodelreleaseeconomics" else res["results"][0]
        return {
            "wallet_local_state": card.get("wallet_local_state"),
            "confirmed_funded_atoms": card.get("confirmed_funded_atoms"),
            "requires_wallet": card.get("requires_wallet"),
        }

    def run_test(self):
        node = self.nodes[0]
        node.createwallet("wa")
        node.createwallet("wb")
        wb = node.get_wallet_rpc("wb")
        self.generatetoaddress(node, 110, wb.getnewaddress())
        target = wb.getnewaddress()
        txid = wb.sendtoaddress(target, wb.getbalance() / 4)
        self.generatetoaddress(node, 1, wb.getnewaddress())
        self.helper.output_script = wb.getaddressinfo(target)["scriptPubKey"]
        tx = wb.gettransaction(txid, False, True)["decoded"]
        funded = sum(int(round(o["value"] * 10**8)) for o in tx["vout"]
                     if o["scriptPubKey"]["hex"] == self.helper.output_script)
        assert funded > 0

        self.log.info("The restriction is in force for wallet RPCs")
        status, out = self.call_as("only_wa", "getwalletinfo", uripath="/wallet/wb")
        assert_equal(status, 500)
        assert_equal(out["error"]["message"], "Requested wallet does not exist or is not loaded")
        status, out = self.call_as("no_wallet", "getwalletinfo")
        assert_equal(status, 500)

        observed = []
        for method in ("getmodelreleaseeconomics", "getfundablemodels"):
            self.log.info(f"{method}: an unrestricted user sees the funding from wb")
            v = self.wallet_view(None, method)
            observed.append(("both-loaded", "unrestricted", method, v))
            for user in USERS:
                v = self.wallet_view(user, method)
                observed.append(("both-loaded", user, method, v))

        self.log.info("Only wb loaded; the restricted users are not authorized for it")
        node.unloadwallet("wa")
        for method in ("getmodelreleaseeconomics", "getfundablemodels"):
            for user in USERS:
                v = self.wallet_view(user, method)
                observed.append(("only-wb-loaded", user, method, v))
        node.loadwallet("wa")

        for row in observed:
            self.log.info("OBS %s", json.dumps(row))
        self.log.info("OBS ingested_by_helper=%d", len(self.helper.ingested))

        for case, user, method, v in observed:
            if user == "unrestricted":
                assert_equal(v["wallet_local_state"], True)
                assert_equal(v["confirmed_funded_atoms"], funded)
                continue
            self.log.info(f"{case} {user} {method}: no state from wb")
            assert v["wallet_local_state"] is not True, (case, user, method, v)
            assert v["confirmed_funded_atoms"] in (None, 0), (case, user, method, v)
            assert v["requires_wallet"] is not True, (case, user, method, v)


if __name__ == "__main__":
    ModelnetWalletRestrictionTest(__file__).main()
