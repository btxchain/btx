#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""A short id must not deadlock the model helper's search lock.

getmodelreleaseeconomics and cacheencryptedmodel hold g_search_mu and then
resolve the caller's id. A 64-hex value is not a 48-byte id, so resolution
looks it up as an alias. That lookup used to lock the same non-recursive
mutex again. The helper thread then stayed blocked: later search and
economy calls timed out until the helper was killed.
"""

import os
import subprocess
from pathlib import Path

from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.util import get_datadir_path

MATMUL_OFF_ARGS = [
    "-regtestmatmulbindingheight=2147483647",
    "-regtestmatmulproductdigestheight=2147483647",
    "-regtestmatmulv4height=2147483647",
    "-regtestmatmulrequireproductpayload=0",
]


class ModelNetSearchLockTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.rpc_timeout = 20
        self.modeld_proc = None
        self.modeld_log = None

    def skip_test_if_missing_module(self):
        self.skip_if_platform_not_posix()
        if self._bin_path("btx-modeld") is None:
            raise SkipTest("btx-modeld not found")

    def _bin_path(self, name):
        exeext = self.config["environment"].get("EXEEXT", "")
        candidates = []
        builddir = self.config["environment"].get("BUILDDIR")
        if builddir:
            candidates.append(Path(builddir) / "bin" / f"{name}{exeext}")
        bitcoind = getattr(self.options, "bitcoind", None)
        if bitcoind:
            candidates.append(Path(bitcoind).resolve().parent / f"{name}{exeext}")
        for cand in candidates:
            if cand.is_file() and os.access(cand, os.X_OK):
                return cand
        return None

    def _start_helper(self):
        datadir = Path(get_datadir_path(self.options.tmpdir, 0))
        datadir.mkdir(parents=True, exist_ok=True)
        modeldir = datadir / "modeldir"
        modeldir.mkdir(parents=True, exist_ok=True)
        self.modeld_socket = modeldir / "modeld.sock"
        if self.modeld_socket.exists():
            self.modeld_socket.unlink()
        argv = [
            str(self._bin_path("btx-modeld")),
            f"-modeldir={modeldir}",
            "-modelstorage=8MiB",
            f"-modelrpcsocket={self.modeld_socket}",
        ]
        self.modeld_log = open(modeldir / "modeld.log", "w", encoding="utf-8")
        self.modeld_proc = subprocess.Popen(
            argv, stdout=self.modeld_log, stderr=subprocess.STDOUT, cwd=str(datadir)
        )

    def _stop_helper(self):
        proc = self.modeld_proc
        self.modeld_proc = None
        if proc is None:
            return
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=max(5.0, 10.0 * float(self.options.timeout_factor)))
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
        if self.modeld_log is not None:
            self.modeld_log.close()
            self.modeld_log = None

    def setup_nodes(self):
        self._start_helper()
        if self.modeld_proc.poll() is not None:
            raise AssertionError(f"btx-modeld exited {self.modeld_proc.returncode}")
        self.extra_args = [[
            "-modelnet=1",
            f"-modelrpcsocket={self.modeld_socket}",
            *MATMUL_OFF_ARGS,
        ]]
        self.add_nodes(self.num_nodes, extra_args=self.extra_args)
        self.start_nodes()

    def shutdown(self):
        self._stop_helper()
        return super().shutdown()

    def run_test(self):
        node = self.nodes[0]
        short_id = "ab" * 32
        card = node.getmodelreleaseeconomics(short_id)
        if not isinstance(card, dict):
            raise AssertionError(f"short id did not return an economics card: {card}")
        try:
            node.cacheencryptedmodel(short_id)
        except JSONRPCException as exc:
            if "helper reply" in str(exc) or "timed out" in str(exc).lower():
                raise AssertionError(f"cacheencryptedmodel wedged the helper: {exc}") from exc
        searched = node.searchmodels({"text": "lock-probe", "scope": "LOCAL", "limit": 1})
        if not isinstance(searched, dict):
            raise AssertionError(f"searchmodels did not answer after the short id: {searched}")
        listed = node.getfundablemodels()
        if not isinstance(listed, dict):
            raise AssertionError(f"getfundablemodels did not answer after the short id: {listed}")
        if self.modeld_proc.poll() is not None:
            raise AssertionError(f"btx-modeld exited {self.modeld_proc.returncode}")


if __name__ == "__main__":
    ModelNetSearchLockTest(__file__).main()
