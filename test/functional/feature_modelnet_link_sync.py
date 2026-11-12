#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""A failed staged-file sync must preserve the previous ModelNet link export."""

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


class ModelnetLinkSyncTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 0
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        if sys.platform != "linux" or shutil.which("cc") is None:
            raise SkipTest("The sync-fault fixture requires Linux and cc")
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
        export_dir = root / "exports"
        export_dir.mkdir()
        gate = export_dir / "arm"
        trace = export_dir / "trace"
        target = export_dir / "link"
        expected_path = export_dir / "expected"
        library = root / "link-sync-fault.so"
        subprocess.run([
            "cc", "-Wall", "-Wextra", "-Werror", "-shared", "-fPIC",
            str(Path(__file__).with_name("modelnet_link_sync_fault.c")),
            "-o", str(library), "-ldl",
        ], check=True, timeout=30)
        args = [
            str(self.helper), f"-modeldir={root / 'models'}", f"-modelrpcsocket={self.socket_path}",
            "-modelstorage=8MiB", "-modellandiscovery=0", "-modelfollowpeers=0",
            "-modelnatpmp=0", "-modelhost=0", "-modelseed=off", "-pwcchain=regtest",
        ]
        env = dict(os.environ, LD_PRELOAD=str(library), HOME=str(root),
                   XDG_DATA_HOME=str(root / "data"), XDG_RUNTIME_DIR=str(root),
                   BTX_TEST_FLUSH_ROOT=str(export_dir))
        with (root / "modeld.log").open("wb") as log:
            proc = subprocess.Popen(args, cwd=root, env=env, stdout=log, stderr=subprocess.STDOUT)
            try:
                self.wait_until(lambda: self.socket_path.exists() or proc.poll() is not None, timeout=10)
                assert_equal(proc.poll(), None)
                assert str(library) in Path(f"/proc/{proc.pid}/maps").read_text()
                model_ids = []
                for tag in ("old", "new"):
                    source = root / tag
                    source.mkdir()
                    header = json.dumps({"__metadata__": {"tag": tag}}).encode()
                    (source / "model.safetensors").write_bytes(struct.pack("<Q", len(header)) + header)
                    model_ids.append(self.rpc("importmodel", [str(source), {"pin": True, "publish": False}])["model_id"])

                method = "exportmodellink"
                self.rpc(method, [model_ids[0], str(target)])
                old_bytes = target.read_bytes()
                target.chmod(0o640)
                self.rpc(method, [model_ids[1], str(expected_path)])
                expected = expected_path.read_bytes()
                assert old_bytes != expected
                trace.unlink(missing_ok=True)
                params = [model_ids[1], str(target)]
                gate.touch()
                try:
                    response = self.rpc(method, params, allow_error=True)
                finally:
                    gate.unlink()
                error = response.get("error")
                self.log.info("Armed export error=%s, old link preserved=%s",
                              error, target.read_bytes() == old_bytes)
                assert_equal((error or {}).get("code"), "IO")
                assert_equal(target.read_bytes(), old_bytes)
                assert_equal(target.stat().st_mode & 0o777, 0o640)
                assert_equal((export_dir / "staged-bytes").read_bytes(), expected)
                fault_events = trace.read_text().splitlines()
                assert_equal(len(fault_events), 1)
                sync_call, armed, size = fault_events[0].split()
                assert sync_call in ("fdatasync", "fsync")
                assert_equal((armed, int(size)), ("1", len(expected)))
                assert_equal(list(export_dir.glob(".btx-export-*.tmp")), [])

                assert_equal(self.rpc(method, params)["written"], True)
                assert_equal(target.read_bytes(), expected)
                assert_equal(target.stat().st_mode & 0o777, 0o640)
                assert_equal(list(export_dir.glob(".btx-export-*.tmp")), [])
                assert_equal(trace.read_text().splitlines()[1:], [f"{sync_call} 0 {len(expected)}", "directory"])
                self.log.info("Retry saved exact link bytes with original permissions and synced the parent directory")
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=5)


if __name__ == "__main__":
    ModelnetLinkSyncTest(__file__).main()
