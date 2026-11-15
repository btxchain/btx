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
        self.last_observation = None
        self.scoped_supported = True
        self.requests = []
        self.read_error = None
        self.refund_height = None
        self.stop_event = threading.Event()
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.bind(path)
        self.sock.listen(16)
        self.sock.settimeout(0.2)

    def card(self, restricted=False):
        card = {"release_id": RELEASE_ID, "output_script": self.output_script, "target_atoms": 100 * 10**8}
        if self.refund_height is not None:
            card["refund_height"] = self.refund_height
        if not restricted and self.last_observation:
            card.update(self.last_observation)
            card["wallet_local_state"] = True
            card["requires_wallet"] = True
        return card

    def reply(self, method, params):
        self.requests.append((method, params))
        restricted = False
        if method == "getrestrictedmodelview":
            if not self.scoped_supported:
                return None, {"code": "METHOD_NOT_FOUND", "message": "unknown model RPC"}
            assert len(params) == 2 and params[0] in FEED_METHODS
            method, params = params
            restricted = True
        if method == "ingestchainfundingobservation":
            self.ingested.append(params[0] if params else None)
            self.last_observation = params[0]
            return {"accepted": True}
        if method in FEED_METHODS:
            if self.read_error:
                return None, self.read_error
            if method in ("getmodeleconomyentry", "getmodelreleaseeconomics"):
                return self.card(restricted)
            return {"results": [self.card(restricted)]}
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
                    error = None
                    if isinstance(result, tuple):
                        result, error = result
                    conn.sendall((json.dumps({"result": result, "error": error, "id": req.get("id")}) + "\n").encode())
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

        # Supported helpers must preserve ordinary read errors.
        self.helper.read_error = {"code": "INVALID_PARAMETER", "message": "invalid release id"}
        for method in ("getmodelreleaseeconomics", "getfundablemodels"):
            params = [RELEASE_ID] if method == "getmodelreleaseeconomics" else [{"limit": 10}]
            try:
                getattr(node, method)(*params)
            except Exception as error:
                assert hasattr(error, "error"), error
                expected = error.error
            else:
                raise AssertionError("Unrestricted invalid read unexpectedly succeeded")
            status, out = self.call_as("no_wallet", method, params)
            assert_equal(status, 500)
            assert_equal(out["error"], expected)
        self.helper.read_error = None

        # A separately managed older helper must refuse the scoped request;
        # the node must not retry the ordinary read and expose its cached view.
        self.helper.scoped_supported = False
        for method in ("getmodelreleaseeconomics", "getfundablemodels"):
            params = [RELEASE_ID] if method == "getmodelreleaseeconomics" else [{"limit": 10}]
            before = len(self.helper.requests)
            status, out = self.call_as("no_wallet", method, params)
            assert_equal(status, 500)
            assert "getrestrictedmodelview" in out["error"]["message"]
            calls = [call for call in self.helper.requests[before:]
                     if call[0] in ("getrestrictedmodelview", "getmodelreleaseeconomics", "getfundablemodels")]
            assert_equal(len(calls), 1)
            assert_equal(calls[0][0], "getrestrictedmodelview")
        self.helper.scoped_supported = True

        self.log.info("A refund_height outside uint32 is unknown, not a wrapped height")
        # 2**32 + 1000000 used to wrap to 1000000 (NOT_MATURE), -1 to 4294967295.
        for refund_height, status in ((1_000_000, "NOT_MATURE"), (2**32 + 1_000_000, "UNKNOWN"), (-1, "UNKNOWN")):
            self.helper.refund_height = refund_height
            card = node.getmodelreleaseeconomics(RELEASE_ID)
            assert_equal((refund_height, card.get("refund_status")), (refund_height, status))
        self.helper.refund_height = None

        self.test_server_path_methods()

    def server_path_calls(self, p):
        """One call per model RPC whose request names a server path.

        The params only have to pass btxd's own argument check; the stub
        helper answers every one of them with {}."""
        pkg = {"path": p}
        return [
            ("importmodel", [p]),
            ("hostmodel", [p]),
            ("previewmodelimport", [p]),
            ("exportmodellink", ["ab" * 48, p]),
            ("qualifymodel", [p]),
            ("scanmodelwatch", [p]),
            ("executemodelimport", [{"source": {"kind": "LOCAL", "locator": p, "snapshot_token": "t"}, "idempotency_key": "k"}]),
            ("resumemodelimport", [{"plan_id": "x"}]),
            ("createbtxpackage", [{"path": p, "idempotency_key": "k"}]),
            ("exportbtxbundle", [{"path": p, "idempotency_key": "k"}]),
            ("exportbtxpackage", [{"path": p, "idempotency_key": "k"}]),
            ("inspectbtxpackage", [pkg]),
            ("verifybtxpackage", [pkg]),
            ("importbtxpackage", [pkg]),
            ("getbtxpackagedocument", [pkg]),
            ("planbtxacquisition", [{"path": p, "local_policy": {"destination": p}}]),
            ("planbtxclientinstall", [pkg]),
            ("planbtxruntime", [pkg]),
            ("executebtxacquisition", [{"plan_id": "x", "verified_local_files": [{"path": "a", "sha384": "00" * 48, "source_path": p}]}]),
            ("setcloudstorage", [{"endpoint": "https://s3.invalid", "bucket": "b", "credential_ref": p, "idempotency_key": "k"}]),
            ("addmodelstorage", [{"endpoint": "https://s3.invalid", "bucket": "b", "credential_ref": p, "idempotency_key": "k"}]),
            ("preparebountyevaluation", [{"artifact_dir": p}]),
            ("runbountyevaluation", [{"plan_id": "x", "approval": True}]),
            ("ensurebtxcapability", [{"typed_params": {"checkout_dir": p}}]),
        ]

    def test_server_path_methods(self):
        node = self.nodes[0]
        refused = "Method not available for wallet-restricted RPC users"
        p = os.path.join(self.options.tmpdir, "no-such-dir", "target")
        calls = self.server_path_calls(p)

        def forwarded(start, method):
            return [call for call in self.helper.requests[start:]
                    if call[0] == method or (call[0] == "getrestrictedmodelview" and call[1] and call[1][0] == method)]

        self.log.info("Model RPCs that name a server path refuse wallet-restricted users before the helper")
        for method, params in calls:
            for user in USERS:
                before = len(self.helper.requests)
                status, out = self.call_as(user, method, params)
                assert_equal((method, user, status), (method, user, 404))
                assert_equal(out["error"]["code"], -32601)
                assert_equal(out["error"]["message"], refused)
                assert_equal(forwarded(before, method), [])
            before = len(self.helper.requests)
            assert_equal(getattr(node, method)(*params), {})
            assert_equal(len(forwarded(before, method)), 1)
        assert not os.path.exists(p)

        self.log.info("Model RPCs without a server path still reach the helper for restricted users")
        for user in USERS:
            before = len(self.helper.requests)
            status, out = self.call_as(user, "listmodels")
            assert_equal(status, 200)
            assert_equal(len(forwarded(before, "listmodels")), 1)

        self.log.info("Every model RPC with a path or dir argument is in the list")
        listed = {method for method, _ in calls}
        names, in_modelnet = [], False
        for line in node.help().splitlines():
            if line.startswith("=="):
                in_modelnet = line.strip("= ").lower() == "modelnet"
            elif in_modelnet and line.strip():
                names.append(line.split()[0])
        assert names
        for name in names:
            args = [line.split()[1] for line in node.help(name).splitlines()
                    if line[:1].isdigit() and ". " in line and len(line.split()) > 1]
            if set(args) & {"path", "dir"}:
                assert name in listed, name



if __name__ == "__main__":
    ModelnetWalletRestrictionTest(__file__).main()
