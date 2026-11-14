#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""encoderesource and decoderesource round trips.

The framework runs nodes with -rpcdoccheck=1, so a result key that the
RPCResult does not document fails the call.
"""

from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.util import assert_equal, assert_raises_rpc_error

KINDS = ["MODEL", "ARTIFACT", "COLLECTION", "IDENTITY", "RELEASE",
         "POLICY_BUNDLE", "CIRCLE", "ALIAS", "PROVIDER"]
# The example in the decoderesource help text.
HELP_EXAMPLE_URI = "btx://pqwy06q0q7wwzy70aeq45sxnlvq3mr067yt4jzphzvnfn2c4zc24zxz665zdprf0nwgskvqq9cq365u9n8l25"


class ModelNetResourceTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-nomodelnet", "-modellandiscovery=0"]]

    def skip_test_if_missing_module(self):
        if not self.config["components"].getboolean("ENABLE_MODELNET"):
            raise SkipTest("ModelNet is not compiled")

    def run_test(self):
        node = self.nodes[0]

        self.log.info("decoderesource on its own help example")
        example = node.decoderesource(HELP_EXAMPLE_URI)
        assert_equal(sorted(example), ["digest", "kind", "schema_version", "uri"])
        assert_equal(example["schema_version"], 2)
        assert_equal(node.encoderesource(example["kind"], example["digest"]), example["uri"])

        self.log.info("encoderesource -> decoderesource for every kind")
        for i, kind in enumerate(KINDS):
            digest = f"{i:02x}" * 48
            uri = node.encoderesource(kind, digest)
            decoded = node.decoderesource(uri)
            assert_equal(decoded["schema_version"], 2)
            assert_equal(decoded["uri"], uri)
            assert_equal(decoded["kind"], kind)
            assert_equal(decoded["digest"], digest)

        self.log.info("a malformed URI is still a parameter error")
        assert_raises_rpc_error(-8, None, node.decoderesource, "btx://not-a-resource")


if __name__ == "__main__":
    ModelNetResourceTest(__file__).main()
