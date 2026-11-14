#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Release views of a wallet-restricted RPC user must not show local funding.

Wallet "pub" funds a release of this node with preparemodelfunding,
signmodelfunding and submitmodelfunding. That records the HTLC output script
and the funding outpoint in the release campaign of the helper. The funding
transaction is on the chain, but these fields tie it to a wallet of this node.

An -rpcauth user restricted to another wallet, or to no wallet ("-"), reads
the release views. They must list the release without the funding txid and
the output script. The unrestricted user still sees both.
"""
import hashlib
import hmac
import http.client
import json
import os
import struct
import urllib.parse

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import str_to_b64str

MATMUL_OFF = [
    "-regtestmatmulbindingheight=2147483647",
    "-regtestmatmulproductdigestheight=2147483647",
    "-regtestmatmulv4height=2147483647",
    "-regtestmatmulrequireproductpayload=0",
]
USERS = {
    # name: (password, wallet restriction)
    "only_wa": ("pw-only-wa", "wa"),
    "no_wallet": ("pw-no-wallet", "-"),
}
READS = ("getmodelreleaseeconomics", "getmodelrelease", "getfundablemodels", "getmodelfeed")


def rpcauth_line(user, password, restriction):
    salt = os.urandom(16).hex()
    digest = hmac.new(salt.encode(), password.encode(), "SHA256").hexdigest()
    return f"-rpcauth={user}:{salt}${digest}:{restriction}"


def write_safetensors(path):
    header = json.dumps({"__metadata__": {"format": "pt"}, "w": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]}}).encode()
    with open(path, "wb") as f:
        f.write(struct.pack("<Q", len(header)) + header + b"\0\0\0\0")


class RpcModelnetRestrictedCampaignFundingTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-modelnet=1", "-modelbind=off", "-modelstorage=8MiB", *MATMUL_OFF]
                           + [rpcauth_line(user, password, restriction) for user, (password, restriction) in USERS.items()]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def call_as(self, user, method, params):
        url = urllib.parse.urlparse(self.nodes[0].url)
        headers = {"Authorization": "Basic " + str_to_b64str(f"{user}:{USERS[user][0]}")}
        conn = http.client.HTTPConnection(url.hostname, url.port, timeout=60)
        conn.request("POST", "/", json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": params}), headers)
        out = json.loads(conn.getresponse().read())
        conn.close()
        assert out.get("error") is None, f"{user} {method}: {out.get('error')}"
        return out["result"]

    def run_test(self):
        node = self.nodes[0]
        self.wait_until(lambda: node.getmodelnetworkinfo().get("helper_ready"), timeout=60)
        node.createwallet("wa")
        node.createwallet("pub")
        pub = node.get_wallet_rpc("pub")
        mine = pub.getnewaddress()
        self.generatetoaddress(node, 110, mine, sync_fun=self.no_op)

        self.log.info("Wallet pub funds a release of this node")
        model_dir = os.path.join(node.datadir_path, "model")
        os.makedirs(model_dir, exist_ok=True)
        path = os.path.join(model_dir, "toy.safetensors")
        write_safetensors(path)
        hosted = node.hostmodel(path)
        height = node.getblockcount()
        secret = hashlib.sha256(b"restricted campaign funding").digest()
        rel = node.createmodelrelease({"uri": hosted["uri"], "secret32_hex": secret.hex(), "refund_height": height + 20,
                                       "target_atoms": 5_000_000, "display_name": "Restricted funding"})
        rid = rel["release_id"]
        key_hash = rel.get("key_hash") or hashlib.sha256(secret).hexdigest()
        claimant = pub.exportpqkey(pub.getnewaddress())["pubkey"]
        refund_pubkey = pub.exportpqkey(pub.getnewaddress())["pubkey"]
        amount = 2_000_000
        frozen = pub.preparemodelfunding(rid, {"key_hash": key_hash, "claimant": claimant, "refund_pubkey": refund_pubkey,
                                               "refund_height": height + 20, "amount_atoms": str(amount),
                                               "fee_cap_atoms": "1000000", "auto_pay": False, "automatic_spend_atoms": "0"})
        signed = pub.signmodelfunding(frozen["unsigned_hex"], frozen)
        pub.submitmodelfunding(signed["hex"], frozen)
        tx = node.decoderawtransaction(signed["hex"])
        out = next(v for v in tx["vout"] if round(v["value"] * 100_000_000) == amount)
        txid = tx["txid"]
        script = out["scriptPubKey"]["hex"]
        self.generatetoaddress(node, 2, mine, sync_fun=self.no_op)

        def params(method):
            if method in ("getmodelreleaseeconomics", "getmodelrelease"):
                return [rid]
            if method == "getfundablemodels":
                return [{"limit": 20}]
            return []

        self.log.info("The unrestricted user sees the funding txid and the output script")
        operator = json.dumps(node.getmodelrelease(rid))
        assert txid in operator and script in operator

        self.log.info("Restricted users see the release without them")
        for user in USERS:
            for method in READS:
                result = json.dumps(self.call_as(user, method, params(method)))
                assert rid in result, f"{user} {method}: release missing"
                assert txid not in result, f"{user} {method}: funding txid visible"
                assert script not in result, f"{user} {method}: output script visible"


if __name__ == "__main__":
    RpcModelnetRestrictedCampaignFundingTest(__file__).main()
