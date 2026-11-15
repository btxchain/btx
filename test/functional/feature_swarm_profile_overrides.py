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

    def test_mirror_cli(self):
        cli = Path(self.config["environment"]["SRCDIR"]) / "contrib/modelnet/btx-model"
        prefix = [sys.executable, str(cli), "--socket", str(self.socket_path), "--json", "mirror"]
        policy_file = self.modeldir / "mirror.json"

        def invoke(args):
            return subprocess.run(prefix + args, capture_output=True, text=True, timeout=30)

        sentinel = {"query": "retained-selector", "keep_latest": 1,
                    "automatic_spend_atoms": 0, "idempotency_key": "mirror-sentinel-regression"}
        assert not self.helper("setmodelmirror", [sentinel]).get("error")
        args = ["--query", "wrapper-selector", "--keep-latest", "3", "--min-independent-origins", "2"]
        result = invoke(args)
        assert result.returncode == 0, (result.stdout, result.stderr)
        stored = json.loads(policy_file.read_text())
        assert any(s["query"] == "retained-selector" and s["keep_latest"] == 1 for s in stored["selectors"])
        assert any(s["query"] == "wrapper-selector" and s["keep_latest"] == 3 for s in stored["selectors"])
        assert_equal(stored["automatic_spend_atoms"], 0)
        assert_equal(stored["min_independent_origins"], 2)

        keyed = args + ["--idempotency-key", "mirror-wrapper-replay-regression"]
        result = invoke(keyed)
        assert result.returncode == 0, (result.stdout, result.stderr)
        saved = policy_file.read_bytes()
        # A replay must not rewrite policy, even with identical contents.
        os.utime(policy_file, ns=(1700000000000000000, 1700000000000000000))
        stamp = policy_file.stat().st_mtime_ns
        result = invoke(keyed)
        assert result.returncode == 0, (result.stdout, result.stderr)
        assert_equal(policy_file.read_bytes(), saved)
        assert_equal(policy_file.stat().st_mtime_ns, stamp)
        conflict = list(keyed)
        conflict[conflict.index("--keep-latest") + 1] = "4"
        result = invoke(conflict)
        assert result.returncode != 0 and "idempotency conflict" in result.stdout.lower(), (result.stdout, result.stderr)
        assert_equal(policy_file.read_bytes(), saved)
        assert_equal(policy_file.stat().st_mtime_ns, stamp)
        result = invoke([])
        assert result.returncode == 0, (result.stdout, result.stderr)
        assert_equal(policy_file.read_bytes(), saved)
        assert_equal(policy_file.stat().st_mtime_ns, stamp)
        for bad_args in (["--query", "bad", "--idempotency-key", ""], ["--idempotency-key", "read-only"]):
            assert invoke(bad_args).returncode == 2
            assert_equal(policy_file.read_bytes(), saved)
        for bad, reason in (({"query": "missing-key", "keep_latest": 2}, "idempotency_key required"),
                            ({"query": "no-spend", "keep_latest": 2, "automatic_spend_atoms": 1,
                              "idempotency_key": "mirror-nonzero-spend-regression"}, "automatic_spend_atoms")):
            reply = self.helper("setmodelmirror", [bad])
            assert reply.get("error") and reason in json.dumps(reply), reply
            assert_equal(policy_file.read_bytes(), saved)
        assert_equal(self.nodes[0].getblockcount(), 0)

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
        self.test_mirror_cli()
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
