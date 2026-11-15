#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""The lab peer routes under /btx-model/3/ take the RPC credential.

They read the same lab store as the lab035 RPC: records the operator wrote
and the bytes of stored models. A loopback source address is not a credential
on a host shared with other users or services, so the routes check the same
Basic credential and -rpcwhitelist entry as a lab035 call.

Regtest only, with -modelnet=0, so no model helper is started.
"""

import hmac
import http.client
import json
import secrets
import urllib.parse

from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.util import assert_equal, str_to_b64str

RECORD_GET = "/btx-model/3/records/get"
HELLO = "/btx-model/3/hello"


def rpcauth_arg(user, password):
    salt = secrets.token_hex(16)
    digest = hmac.new(salt.encode(), password.encode(), "SHA256").hexdigest()
    return f"-rpcauth={user}:{salt}${digest}"


class LabPeerAuthTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.lab_user, self.lab_password = "labreader", secrets.token_hex(16)
        self.chain_user, self.chain_password = "chainreader", secrets.token_hex(16)
        self.extra_args = [[
            "-modelnet=0",
            rpcauth_arg(self.lab_user, self.lab_password),
            rpcauth_arg(self.chain_user, self.chain_password),
            f"-rpcwhitelist={self.lab_user}:lab035",
            f"-rpcwhitelist={self.chain_user}:getblockcount",
            "-rpcwhitelistdefault=0",
        ]]

    def post(self, path, body, auth=None):
        url = urllib.parse.urlparse(self.nodes[0].url)
        conn = http.client.HTTPConnection(url.hostname, url.port)
        headers = {"Content-Type": "application/json"}
        if auth is not None:
            headers["Authorization"] = f"Basic {str_to_b64str(auth)}"
        conn.request("POST", path, body, headers)
        response = conn.getresponse()
        data = response.read().decode()
        conn.close()
        return response.status, data

    def run_test(self):
        node = self.nodes[0]
        if "lab035" not in node.help():
            raise SkipTest("built without ModelNet")
        url = urllib.parse.urlparse(node.url)
        owner = f"{url.username}:{url.password}"

        self.log.info("Store one lab record through the lab035 RPC")
        record_id = secrets.token_hex(48)
        marker = "lab-peer-auth-" + secrets.token_hex(8)
        stored = node.lab035("lab.incident_publish", json.dumps({
            "incident_id": record_id,
            "audience": marker,
            "idempotency_key": "lab-peer-auth-0001",
            "expected_state": None,
        }))
        assert_equal(stored["result"]["state"], "PUBLISHED")
        body = json.dumps({"record_id": record_id})

        self.log.info("Without a credential the route is 401 and returns nothing")
        status, data = self.post(RECORD_GET, body)
        assert_equal(status, 401)
        assert marker not in data

        self.log.info("A wrong password is 401")
        status, data = self.post(RECORD_GET, body, f"{url.username}:wrong")
        assert_equal(status, 401)
        assert marker not in data

        self.log.info("A whitelisted user without lab035 is 403")
        status, data = self.post(RECORD_GET, body, f"{self.chain_user}:{self.chain_password}")
        assert_equal(status, 403)
        assert marker not in data

        self.log.info("The node credential and a lab035 user read the record")
        for auth in (owner, f"{self.lab_user}:{self.lab_password}"):
            status, data = self.post(RECORD_GET, body, auth)
            assert_equal(status, 200)
            reply = json.loads(data)
            assert_equal(reply["record_id"], record_id)
            assert marker in reply["body"]

        self.log.info("The other routes take the same check")
        hello = json.dumps({
            "contract_revision": "1.1.0",
            "protocol_versions": [3],
            "mode": "PUBLIC_READER",
            "nonce": secrets.token_hex(32),
            "transport_binding_id": None,
            "requested_roles": ["PUBLIC_READ"],
            "control_limit": 32768,
            "data_limit": 65536,
            "server_deadline_ms": None,
            "proof_window_ms": 1000,
        })
        assert_equal(self.post(HELLO, hello)[0], 401)
        assert_equal(self.post(HELLO, hello, owner)[0], 200)


if __name__ == '__main__':
    LabPeerAuthTest(__file__).main()
