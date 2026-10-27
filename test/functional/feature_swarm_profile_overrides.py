#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers. Distributed under the MIT license.
"""CLI profile overrides persist and change real helper policy, without money authority."""
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class SwarmProfileOverridesTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def setup_nodes(self):
        self.modeldir = Path(self.options.tmpdir) / "models"
        self.extra_args = [[f"-modeldir={self.modeldir}", "-modelbind=off"]]
        super().setup_nodes()
        requested = self.nodes[0].datadir_path / self.chain / "modelnet" / "modeld.sock"
        encoded = os.fsencode(requested)
        # Matches UnixRpcListenPath: a sun_path that does not fit is hashed
        # into the private runtime directory. An explicit -modelrpcsocket would
        # stop btxd from owning the helper.
        if len(encoded) >= 108:
            runtime = os.environ.get("XDG_RUNTIME_DIR")
            digest = hashlib.sha256(encoded).digest()[:8].hex()
            self.socket_path = Path(runtime) / "btx-modeld" / f"{digest}.sock"
        else:
            self.socket_path = requested

    def setup_network(self):
        self.setup_nodes()

    def skip_test_if_missing_module(self):
        self.skip_if_platform_not_posix()

    def helper(self, method, params):
        request = {"jsonrpc": "1.0", "id": "profile-native", "method": method, "params": params}
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(15)
            client.connect(str(self.socket_path))
            client.sendall((json.dumps(request) + "\n").encode())
            client.shutdown(socket.SHUT_WR)
            with client.makefile("rb") as stream:
                raw = stream.readline(1024 * 1024)
        return json.loads(raw)

    def ready(self):
        self.wait_until(lambda: self.nodes[0].getmodelnetworkinfo().get("helper_ready") is True, timeout=60)

    def run_test(self):
        self.ready()
        node = self.nodes[0]
        assert_equal(node.getmodelnetworkinfo()["quota_bytes"], 1024 ** 3)
        cli = Path(self.config["environment"]["SRCDIR"]) / "contrib/modelnet/btx-model"
        result = subprocess.run([sys.executable, str(cli), "--socket", str(self.socket_path),
                                 "--json", "profile", "set", "custom", json.dumps({"storage_bytes": "8MiB",
                                 "follow_peers": False, "seed": "off", "upload_bps": "1MiB"})],
                                capture_output=True, text=True, timeout=30)
        assert result.returncode == 0, (result.stdout, result.stderr)
        assert isinstance(json.loads(result.stdout), dict)
        self.wait_until(lambda: node.getmodelnetworkinfo()["quota_bytes"] == 8 * 1024 ** 2, timeout=10)
        stored = self.helper("getmodelprofile", [])["result"]
        assert_equal(stored["storage_arg"], "8388608")
        assert_equal(stored["follow_peers"], False)
        assert_equal(stored["seed"], "off")
        policy_file = self.modeldir / "operator_profile.json"
        original = policy_file.read_bytes()
        for changes in ({"automatic_spend_atoms": 1}, {"storage_bytes": -1},
                        {"relay": "yes"}, {"wallet": True},
                        {"storage_arg": "0", "storage_bytes": "1MiB"}):
            reply = self.helper("setmodelprofile", [{"profile": "custom", **changes}])
            assert reply.get("error"), reply
            assert_equal(policy_file.read_bytes(), original)
        self.restart_node(0)
        self.ready()
        assert_equal(node.getmodelnetworkinfo()["quota_bytes"], 8 * 1024 ** 2)
        reply = self.helper("setmodelprofile", ["custom", {"storage_bytes": 0, "follow_peers": False}])
        assert not reply.get("error"), reply
        self.wait_until(lambda: node.getmodelnetworkinfo()["quota_bytes"] == 0, timeout=10)
        assert_equal(node.getmodelnetworkinfo()["automatic_spend_atoms"], 0)
        assert_equal(node.getblockcount(), 0)
        # An inspection request may not invoke the helper's action executor.
        for _ in range(2):
            peek = self.helper("getmodelwatchactions", [{"drain": False}])["result"]
            assert_equal(peek["drained"], False)
            assert_equal(peek["executed_free_downloads"], False)
            assert_equal(peek["automatic_spend_atoms"], 0)
        guard_file = self.modeldir / "swarm" / "guard-process.json"
        self.wait_until(lambda: guard_file.is_file() and json.loads(guard_file.read_text()).get("ready") is True, timeout=30)
        running = json.loads(guard_file.read_text())
        assert running["observed_at_ms"] <= time.time_ns() // 1_000_000 < running["valid_until_ms"]
        assert_equal(running["state"], "READY")
        assert_equal(running["execution_authorized"], False)
        self.stop_node(0)
        stopped = json.loads(guard_file.read_text())
        assert_equal(stopped["state"], "STOPPED")
        assert_equal(stopped["enabled"], False)
        assert_equal(stopped["ready"], False)
        assert_equal(stopped["pid"], -1)
        assert stopped["heartbeat_sequence"] > running["heartbeat_sequence"]


if __name__ == "__main__":
    SwarmProfileOverridesTest(__file__).main()
