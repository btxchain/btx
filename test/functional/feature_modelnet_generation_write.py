#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""A short generation sidecar write must fail capability materialization."""

import json
import os
import shutil
import socket
import subprocess
import sys
from pathlib import Path

from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.util import assert_equal


class ModelnetGenerationWriteTest(BitcoinTestFramework):
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

    def rpc(self, method, params, *, allow_error=False):
        request = {"jsonrpc": "1.0", "id": 1, "method": method, "params": params}
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(10)
            client.connect(str(self.socket_path))
            client.sendall(json.dumps(request).encode() + b"\n")
            with client.makefile("rb") as stream:
                reply = json.loads(stream.readline(1024 * 1024))
        assert_equal(reply["id"], 1)
        if allow_error:
            return reply
        assert_equal(reply.get("error"), None)
        return reply["result"]

    def run_test(self):
        root = Path(self.options.tmpdir).resolve()
        self.socket_path = root / "m.sock"
        scratch = root / "scratch"
        scratch.mkdir()
        staged = scratch / "btx-capability-ensure"
        gate = root / "inject"
        library = root / "generation-write-fault.so"
        subprocess.run([
            "cc", "-Wall", "-Wextra", "-Werror", "-shared", "-fPIC",
            str(Path(__file__).with_name("modelnet_generation_write_fault.c")),
            "-o", str(library), "-ldl",
        ], check=True, timeout=30)
        args = [
            str(self.helper), f"-modeldir={root / 'models'}", f"-modelrpcsocket={self.socket_path}",
            "-modelstorage=8MiB", "-modellandiscovery=0", "-modelfollowpeers=0",
            "-modelnatpmp=0", "-modelhost=0", "-modelseed=off", "-pwcchain=regtest",
        ]
        env = dict(os.environ, LD_PRELOAD=str(library), HOME=str(root),
                   XDG_DATA_HOME=str(root / "data"), XDG_RUNTIME_DIR=str(root),
                   TMPDIR=str(scratch), BTX_TEST_GENERATION_GATE=str(gate),
                   BTX_TEST_GENERATION_STORE=str(staged) + "/")
        with (root / "modeld.log").open("wb") as log:
            proc = subprocess.Popen(args, cwd=root, env=env, stdout=log, stderr=subprocess.STDOUT)
            try:
                self.wait_until(lambda: self.socket_path.exists() or proc.poll() is not None, timeout=10)
                assert_equal(proc.poll(), None)
                grant = {"caller": "local", "host_bytes": 8388608, "automatic_spend_atoms": 0}
                recipe = {
                    "recipe_kind": "FULL_MODEL",
                    "components": [{
                        "name": "base", "role": "BASE", "required": True,
                        "resource": {"kind": "MODEL", "digest48": "a" * 96},
                    }],
                    "readiness_contract": "FULL_REQUIRED_SET",
                }
                plan = self.rpc("planbtxcapability", {"recipe": recipe, "grant": grant})
                request = {"plan_id": plan["plan_id"], "grant": grant, "automatic_spend_atoms": 0}
                method = "ensurebtxcapability"
                assert self.rpc(method, request)["lease_id"]
                gate.touch()
                try:
                    response = self.rpc(method, request, allow_error=True)
                finally:
                    gate.unlink()
                assert "generation fixture: EIO" in (root / "modeld.log").read_text(encoding="utf-8")
                error = response.get("error")
                self.log.info("Generation fault: error=%s lease=%s",
                              error, bool((response.get("result") or {}).get("lease_id")))
                assert_equal((error or {}).get("code"), "IO_ERROR")
                assert_equal(list(staged.iterdir()), [])
                assert self.rpc(method, request)["lease_id"]
                assert_equal(list(staged.iterdir()), [])
                self.log.info("Identical retry returned a lease and left no staged files")
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=5)


if __name__ == "__main__":
    ModelnetGenerationWriteTest(__file__).main()
