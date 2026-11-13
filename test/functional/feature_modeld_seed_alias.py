#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""btx-modeld: -modelseedupondownload is only an alias of -modelseed.

doc/modelnet/propagation.md: "-modelseedupondownload=0|1 ... 1 -> auto, 0 -> off.
Not a second opt-in; ignored when -modelseed is set". The test starts a
btx-modeld per flag combination (unix RPC only: no -modelbind, no NAT-PMP, no
LAN discovery) and reads seed_mode from getmodelnetworkinfo.
"""
import json
import os
import socket
import subprocess
import time
from pathlib import Path

from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.util import assert_equal


class ModeldSeedAliasTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 0

    def skip_test_if_missing_module(self):
        self.skip_if_platform_not_posix()
        if self.modeld_path() is None:
            raise SkipTest("btx-modeld not found")

    def setup_network(self):
        pass

    def modeld_path(self):
        exeext = self.config["environment"].get("EXEEXT", "")
        name = f"btx-modeld{exeext}"
        builddir = self.config["environment"].get("BUILDDIR")
        candidates = [Path(builddir) / "bin" / name] if builddir else []
        bitcoind = getattr(self.options, "bitcoind", None)
        if bitcoind:
            candidates.append(Path(bitcoind).resolve().parent / name)
        for cand in candidates:
            if cand.is_file() and os.access(cand, os.X_OK):
                return cand
        return None

    def unix_rpc(self, sock_path, method):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(30)
            s.connect(str(sock_path))
            s.sendall((json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": []}) + "\n").encode())
            raw = b""
            while not raw.endswith(b"\n"):
                chunk = s.recv(65536)
                if not chunk:
                    break
                raw += chunk
        reply = json.loads(raw)
        assert reply.get("error") is None, reply
        return reply["result"]

    def seed_mode(self, label, flags):
        """seed_mode of a btx-modeld started with flags."""
        modeldir = Path(self.options.tmpdir) / label
        modeldir.mkdir(parents=True)
        sock_path = modeldir / "modeld.sock"
        argv = [str(self.modeld_path()), f"-modeldir={modeldir}", "-modelstorage=8MiB", f"-modelrpcsocket={sock_path}",
                "-modelnatpmp=0", "-modellandiscovery=0", *flags]
        with open(modeldir / "modeld.log", "w", encoding="utf-8") as log:
            proc = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT, cwd=str(modeldir))
            try:
                deadline = time.time() + 30
                while not sock_path.exists():
                    assert proc.poll() is None, f"btx-modeld {flags} exited {proc.returncode}"
                    assert time.time() < deadline, f"btx-modeld {flags}: no socket"
                    time.sleep(0.1)
                return self.unix_rpc(sock_path, "getmodelnetworkinfo")["seed_mode"]
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=5)

    def run_test(self):
        self.log.info("The alias alone sets the seed mode")
        assert_equal(self.seed_mode("alias-1", ["-modelseedupondownload=1"]), "auto")
        assert_equal(self.seed_mode("alias-0", ["-modelseedupondownload=0"]), "off")

        self.log.info("With -modelseed set, the alias is ignored, in either order")
        assert_equal(self.seed_mode("off-then-1", ["-modelseed=off", "-modelseedupondownload=1"]), "off")
        assert_equal(self.seed_mode("1-then-off", ["-modelseedupondownload=1", "-modelseed=off"]), "off")
        assert_equal(self.seed_mode("manual-then-0", ["-modelseed=manual", "-modelseedupondownload=0"]), "manual")


if __name__ == '__main__':
    ModeldSeedAliasTest(__file__).main()
