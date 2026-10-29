#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""btx-capabilityd keeps its socket and catalog private under a umask of 0022.

btx-modeld sets umask(0077) at start. btx-capabilityd did not, so with the
common umask of 0022 its unix socket was srwxr-xr-x and the model directory
and catalog files were readable by every local user.
"""

import os
import stat
import subprocess
import time
from pathlib import Path

from test_framework.test_framework import BitcoinTestFramework, SkipTest


class CapabilitydFileModesTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 0

    def setup_network(self):
        pass

    def run_test(self):
        if os.name == "nt":
            raise SkipTest("unix socket and file modes only")
        capd = Path(os.getenv("BTX_CAPABILITYD", Path(self.config["environment"]["BUILDDIR"]) / "bin" / "btx-capabilityd"))
        if not capd.exists():
            raise SkipTest(f"{capd} not built")
        modeldir = Path(self.options.tmpdir) / "capdir"
        sock = Path(self.options.tmpdir) / "cap.sock"
        old = os.umask(0o022)
        try:
            proc = subprocess.Popen([str(capd), f"-modeldir={modeldir}", f"-capabilitysocket={sock}"],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        finally:
            os.umask(old)
        try:
            deadline = time.time() + 30
            while not sock.exists():
                assert proc.poll() is None, f"btx-capabilityd exited {proc.returncode}"
                assert time.time() < deadline, "capability socket did not appear"
                time.sleep(0.1)
            time.sleep(0.5)
            paths = [sock, modeldir] + sorted(modeldir.rglob("*"))
            for p in paths:
                mode = stat.S_IMODE(os.lstat(p).st_mode)
                self.log.info(f"{oct(mode)} {p.name}")
                assert mode & 0o077 == 0, f"{p} is {oct(mode)}, readable by group or others"
        finally:
            proc.terminate()
            proc.wait(timeout=30)


if __name__ == "__main__":
    CapabilitydFileModesTest(__file__).main()
