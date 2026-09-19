#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""LOCAL-04/05 first-run: quota 0 refuses import; 8MiB quota stores payload.

Isolated helper only. Never production btxd. automatic_spend_atoms stays 0.
"""

import json
import os
import socket
import struct
import subprocess
from pathlib import Path

from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.util import get_datadir_path

MATMUL_OFF_ARGS = [
    "-regtestmatmulbindingheight=2147483647",
    "-regtestmatmulproductdigestheight=2147483647",
    "-regtestmatmulv4height=2147483647",
    "-regtestmatmulrequireproductpayload=0",
]


class ModelNetFirstRunTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-nomodelnet", "-modelnet=0", *MATMUL_OFF_ARGS]]
        self.modeld_proc = None
        self.modeld_log = None

    def setup_nodes(self):
        self.add_nodes(self.num_nodes, extra_args=self.extra_args)
        self.start_nodes()

    def skip_test_if_missing_module(self):
        self.skip_if_platform_not_posix()
        if self._modeld_path() is None:
            raise SkipTest("btx-modeld missing")

    def _modeld_path(self):
        exeext = self.config["environment"].get("EXEEXT", "")
        builddir = self.config["environment"].get("BUILDDIR")
        cand = Path(builddir) / "bin" / f"btx-modeld{exeext}"
        if cand.is_file() and os.access(cand, os.X_OK):
            return cand
        return None

    def _start_helper(self, modeldir, extra):
        modeldir.mkdir(parents=True, exist_ok=True)
        sock = modeldir / "modeld.sock"
        if sock.exists():
            sock.unlink()
        argv = [str(self._modeld_path()), f"-modeldir={modeldir}", f"-modelrpcsocket={sock}", *extra]
        self.modeld_log = open(modeldir / "modeld.log", "w", encoding="utf-8")
        self.modeld_proc = subprocess.Popen(argv, stdout=self.modeld_log, stderr=subprocess.STDOUT)
        self.modeld_socket = sock

    def _stop_helper(self):
        proc = self.modeld_proc
        self.modeld_proc = None
        if proc is None:
            return
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=8)
            except subprocess.TimeoutExpired:
                proc.kill()
        if self.modeld_log:
            self.modeld_log.close()
            self.modeld_log = None

    def shutdown(self):
        self._stop_helper()
        return super().shutdown()

    def _unix(self, method, params=None):
        req = {"jsonrpc": "1.0", "id": "fr", "method": method, "params": params if params is not None else []}
        wire = (json.dumps(req, separators=(",", ":")) + "\n").encode()
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            client.settimeout(15)
            client.connect(str(self.modeld_socket))
            client.sendall(wire)
            client.shutdown(socket.SHUT_WR)
            chunks = []
            while True:
                buf = client.recv(65536)
                if not buf:
                    break
                chunks.append(buf)
                if b"\n" in buf:
                    break
        finally:
            client.close()
        return json.loads(b"".join(chunks).split(b"\n", 1)[0].decode())

    def _wait_ready(self):
        import time
        for _ in range(50):
            if self.modeld_proc.poll() is not None:
                raise AssertionError(f"btx-modeld died {self.modeld_proc.returncode}")
            try:
                reply = self._unix("getmodelnetworkinfo")
            except OSError:
                time.sleep(0.1)
                continue
            info = reply.get("result") or {}
            if info.get("helper_ready"):
                spend = info.get("automatic_spend_atoms", 0)
                if spend not in (0, "0"):
                    raise AssertionError(f"spend {spend}")
                return info
            time.sleep(0.1)
        raise AssertionError("helper_ready timeout")

    def run_test(self):
        src = Path(self.options.tmpdir) / "src" / "model.safetensors"
        src.parent.mkdir(parents=True, exist_ok=True)
        src.write_bytes(struct.pack("<Q", 2) + b"{}")

        zero = Path(get_datadir_path(self.options.tmpdir, 0)) / "zero"
        self._start_helper(zero, ["-modelstorage=0"])
        try:
            info = self._wait_ready()
            quota = int(info.get("quota_bytes") or 0)
            if quota != 0:
                raise AssertionError(f"quota0 expected 0 got {quota}")
            denied = self._unix("importmodel", [str(src)])
            if not denied.get("error"):
                raise AssertionError(f"quota 0 must refuse import: {denied}")
            self.log.info("firstrun quota0 import refused: %s", denied["error"])
        finally:
            self._stop_helper()

        pos = Path(get_datadir_path(self.options.tmpdir, 0)) / "pos"
        self._start_helper(pos, ["-modelstorage=8MiB"])
        try:
            info = self._wait_ready()
            if int(info.get("quota_bytes") or 0) < 8 * 1024 * 1024:
                raise AssertionError(f"quota 8MiB: {info}")
            imported = self._unix("importmodel", [str(src)])
            if denied_err := imported.get("error"):
                raise AssertionError(f"quota 8MiB import: {denied_err}")
            result = imported["result"]
            if result.get("automatic_spend_atoms") not in (0, "0", None):
                raise AssertionError(f"import spend {result}")
            listed = self._unix("listmodels")
            models = (listed.get("result") or {}).get("models") or []
            if not models:
                raise AssertionError(f"listmodels empty: {listed}")
            self.log.info("firstrun positive import models=%s", len(models))
        finally:
            self._stop_helper()

        chain = self.nodes[0].getblockchaininfo()
        if chain.get("chain") != "regtest":
            raise AssertionError(f"chain {chain}")
        self.log.info("feature_modelnet_firstrun passed")


if __name__ == "__main__":
    ModelNetFirstRunTest(__file__).main()
