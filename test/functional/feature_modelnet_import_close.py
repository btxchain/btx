#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""A failed buffered close must not verify a partial hashless model import."""

import json
import os
import shutil
import socket
import struct
import subprocess
import sys
from pathlib import Path

from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.util import assert_equal


class ModelnetImportCloseTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 0
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        if sys.platform != "linux" or shutil.which("cc") is None:
            raise SkipTest("The close-fault fixture requires Linux and cc")
        self.helper = Path(self.config["environment"]["BUILDDIR"]) / "bin" / "btx-modeld"
        if not os.access(self.helper, os.X_OK):
            raise SkipTest("btx-modeld not found")

    def setup_network(self):
        pass

    def rpc(self, method, params):
        request = {"jsonrpc": "1.0", "id": 1, "method": method, "params": params}
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(10)
            client.connect(str(self.socket_path))
            client.sendall(json.dumps(request).encode() + b"\n")
            with client.makefile("rb") as stream:
                reply = json.loads(stream.readline(1024 * 1024))
        assert_equal(reply["id"], 1)
        assert_equal(reply.get("error"), None)
        return reply["result"]

    def import_plan(self, tag):
        return {
            "plan_id": tag * 96,
            "idempotency_key": "stage-close-" + tag,
            "source": {
                "kind": "HUGGINGFACE",
                "locator": "https://huggingface.co/example/fixture",
                "snapshot_token": "local-fixture",
                "resolved_revision": "fixture",
            },
            "origins": [
                {"type": "local", "locator": str(path), "snapshot_token": "fixture", "priority": i}
                for i, path in enumerate((self.source, self.source.with_name("unused.safetensors")))
            ],
            "files": [{"source_path": "model.safetensors", "size_bytes": len(self.data)}],
        }

    def execute(self, tag, fault=False):
        before = set(self.store.rglob("model.safetensors"))
        if fault:
            self.gate.touch()
        try:
            result = self.rpc("executemodelimport", [self.import_plan(tag)])
        finally:
            self.gate.unlink(missing_ok=True)
        files = set(self.store.rglob("model.safetensors")) - before
        return result, [path.read_bytes() for path in files]

    def run_test(self):
        root = Path(self.options.tmpdir).resolve()
        self.store = root / "models"
        self.source = root / "source.safetensors"
        self.gate = root / "inject"
        self.socket_path = root / "m.sock"
        header = b'{"__metadata__":{"tag":"local-close-control"}}'.ljust(632)
        self.data = struct.pack("<Q", len(header)) + header
        self.source.write_bytes(self.data)

        library = root / "import-close-fault.so"
        subprocess.run([
            "cc", "-Wall", "-Wextra", "-Werror", "-shared", "-fPIC",
            str(Path(__file__).with_name("modelnet_import_close_fault.c")),
            "-o", str(library), "-ldl",
        ], check=True, timeout=30)
        args = [
            str(self.helper), f"-modeldir={self.store}", f"-modelrpcsocket={self.socket_path}",
            "-modelstorage=8MiB", "-modellandiscovery=0", "-modelfollowpeers=0",
            "-modelnatpmp=0", "-modelhost=0", "-modelseed=off", "-pwcchain=regtest",
        ]
        env = dict(os.environ, LD_PRELOAD=str(library), HOME=str(root),
                   XDG_DATA_HOME=str(root / "data"), XDG_RUNTIME_DIR=str(root),
                   BTX_TEST_IMPORT_FAULT_GATE=str(self.gate), BTX_TEST_IMPORT_STORE=str(self.store) + "/")
        with (root / "modeld.log").open("wb") as log:
            proc = subprocess.Popen(args, cwd=root, env=env, stdout=log, stderr=subprocess.STDOUT)
            try:
                self.wait_until(lambda: self.socket_path.exists() or proc.poll() is not None, timeout=10)
                assert_equal(proc.poll(), None)
                healthy, outputs = self.execute("a")
                assert_equal(healthy["imported"], True)
                assert_equal(outputs, [self.data])

                result, outputs = self.execute("b", fault=True)
                assert_equal(outputs, [self.data[:320]])
                assert_equal(self.source.read_bytes(), self.data)
                status = self.rpc("getmodelimport", [{"plan_id": "b" * 96}])

                retry, outputs = self.execute("c")
                assert_equal(retry["imported"], True)
                assert_equal(retry["model_id"], healthy["model_id"])
                assert_equal(outputs, [self.data])
                self.log.info("Fault result: stage_error=%s phase=%s verified=%s",
                              result.get("stage_error"), status["phase"], status["has_verified_manifest"])
                assert_equal(result.get("stage_error"), "close")
                assert_equal(status["has_verified_manifest"], False)
                assert_equal(status["phase"], "STAGING")
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=5)


if __name__ == "__main__":
    ModelnetImportCloseTest(__file__).main()
