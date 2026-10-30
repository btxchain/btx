#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see COPYING.
"""Real multicast -> PQ1 -> automatic verified model acquisition regression.

Four native btxd/modeld processes share one host. No model peer address is
provided. This is a socket/process integration test, not evidence of physical
LAN separation, WAN reachability, or an Internet-disconnected deployment.
MatMul and monetary consensus settings are left intact. With --onlynet=ipv4
every node also runs with -onlynet=ipv4: a LAN peer counts as an IPv4 peer.
"""

import json
import os
from pathlib import Path
import socket
import struct

from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.util import assert_equal


def write_safetensors(path, values):
    header = json.dumps({
        "__metadata__": {"format": "pt", "purpose": "native transport regression"},
        "weight": {"dtype": "F32", "shape": [2, 3], "data_offsets": [0, 24]},
    }, separators=(",", ":")).encode()
    path.write_bytes(struct.pack("<Q", len(header)) + header + struct.pack("<6f", *values))


class SwarmLanDiscoverTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 4
        self.setup_clean_chain = True
        self.rpc_timeout = 180

    def add_options(self, parser):
        parser.add_argument("--onlynet", action="append", default=[],
                            help="pass -onlynet=<net> to every node")

    def skip_test_if_missing_module(self):
        self.skip_if_platform_not_posix()
        builddir = Path(self.config["environment"]["BUILDDIR"])
        suffix = self.config["environment"].get("EXEEXT", "")
        for name in ("btx-modeld", "btx-guardd"):
            binary = builddir / "bin" / (name + suffix)
            assert binary.is_file() and os.access(binary, os.X_OK), f"build required native helper: {binary}"

    def setup_nodes(self):
        self.modeldirs = [Path(self.options.tmpdir) / f"models-{i}" for i in range(self.num_nodes)]
        self.extra_args = []
        sockets = []
        try:
            for i, modeldir in enumerate(self.modeldirs):
                modeldir.mkdir(parents=True)
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.bind(("0.0.0.0", 0))
                sockets.append(sock)
                # The monetary framework puts connect=0 in its isolated test
                # config. Explicitly permit model LAN discovery only; provide
                # neither a peer address nor a modelnet/storage enable flag.
                args = [f"-modeldir={modeldir}", f"-modelbind=0.0.0.0:{sock.getsockname()[1]}",
                        "-modellandiscovery=1"]
                if i == 3:
                    args.append("-modelstorage=0")
                args += [f"-onlynet={net}" for net in self.options.onlynet]
                self.extra_args.append(args)
        finally:
            for sock in sockets:
                sock.close()
        super().setup_nodes()

    def setup_network(self):
        self.setup_nodes()

    @staticmethod
    def native(node):
        return node.getmodelnetworkinfo()["native_participation"]

    @staticmethod
    def verified(node, model_id):
        return any(item.get("model_id") == model_id and item.get("bytes_verified") is True
                   and item.get("incomplete") is False for item in node.listmodels().get("models", []))

    def guard_ready(self, index):
        path = self.modeldirs[index] / "swarm" / "guard-process.json"
        if not path.is_file():
            return False
        try:
            status = json.loads(path.read_text())
        except (OSError, ValueError):
            return False
        return (status.get("ready") is True and status.get("pid", -1) > 0
                and status.get("transport") == "PRIVATE_INHERITED_STDIO")

    def run_test(self):
        for node in self.nodes:
            self.wait_until(lambda node=node: node.getmodelnetworkinfo().get("helper_ready") is True, timeout=60)
            info = node.getmodelnetworkinfo()
            assert_equal(info["pq1_ready"], True)
            assert_equal(info["automatic_spend_atoms"], 0)
            native = info["native_participation"]
            if not native["lan_enabled"]:
                raise SkipTest("native LAN unavailable on this host: " + native.get("lan_error", "unknown"))
            assert_equal(native["release_qualified"], False)
        for index in range(self.num_nodes):
            self.wait_until(lambda index=index: self.guard_ready(index), timeout=30)
        for node in self.nodes[:3]:
            assert_equal(node.getmodelnetworkinfo()["quota_bytes"], 1024 ** 3)
        assert_equal(self.nodes[3].getmodelnetworkinfo()["quota_bytes"], 0)

        self.wait_until(lambda: all(self.native(node)["authenticated_peers"] >= 3 for node in self.nodes), timeout=120)
        for node in self.nodes:
            observations = self.native(node)["peer_observations"]
            assert len({peer["transport_pin"] for peer in observations}) >= 3
            assert all(peer["compute_authorized"] is False for peer in observations)
            assert_equal(node.getpeerinfo(), [])

        first = Path(self.options.tmpdir) / "first.safetensors"
        write_safetensors(first, [1, 2, 3, 4, 5, 6])
        hosted = self.nodes[0].hostmodel(str(first))
        model_id = hosted["model_id"]
        # Empty followers acquire without getmodel, addmodelnode, or manual
        # copying. Catalog verification is the acceptance criterion.
        self.wait_until(lambda: all(self.verified(node, model_id) for node in self.nodes[:3]), timeout=120)
        self.wait_until(lambda: all(any(family["model_id"] == model_id
                                      and len(family["peer_transport_pins"]) >= 2
                                      for family in self.native(node)["shared_model_families"])
                                   for node in self.nodes[:3]), timeout=90)
        assert_equal(self.nodes[3].getmodelnetworkinfo()["used_bytes"], 0)
        assert_equal(self.verified(self.nodes[3], model_id), False)

        # The original publisher disappears. A remaining process publishes
        # different bytes and another follower must discover/acquire them.
        self.stop_node(0)
        second = Path(self.options.tmpdir) / "after-bootstrap-loss.safetensors"
        write_safetensors(second, [7, 8, 9, 10, 11, 12])
        next_id = self.nodes[1].hostmodel(str(second))["model_id"]
        assert next_id != model_id
        self.wait_until(lambda: self.verified(self.nodes[2], next_id), timeout=120)
        assert self.native(self.nodes[2])["acquired_models"] >= 2
        for node in self.nodes[1:]:
            assert_equal(node.getmodelnetworkinfo()["automatic_spend_atoms"], 0)
            assert_equal(node.getblockcount(), 0)
        assert_equal(self.nodes[3].getmodelnetworkinfo()["used_bytes"], 0)
        self.log.info("PASS: same-host native LAN/PQ1, verified free acquisition, observer family, "
                      "guard ownership, zero storage policy, and original-publisher loss; physical hosts not qualified")


if __name__ == "__main__":
    SwarmLanDiscoverTest(__file__).main()
