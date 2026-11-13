#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""A safetensors file with a bad header in the -modelwatch folder must not end btx-modeld.

The watch scan runs in the helper's main loop, outside any RPC. A header
whose shape or data_offsets hold a string used to throw out of the header
parser, end the helper, and end it again after every restart.
"""

import json
import os
import struct
import time
from pathlib import Path

from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.util import assert_equal

MATMUL_OFF = [
    "-regtestmatmulbindingheight=2147483647",
    "-regtestmatmulproductdigestheight=2147483647",
    "-regtestmatmulv4height=2147483647",
    "-regtestmatmulrequireproductpayload=0",
]
SCAN_S = 5


def write_safetensors(path, header):
    raw = json.dumps(header).encode()
    path.write_bytes(struct.pack("<Q", len(raw)) + raw + b"\0" * 4)


class ModelnetWatchBadHeaderTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def setup_nodes(self):
        self.watch = Path(self.options.tmpdir) / "watch"
        self.watch.mkdir(parents=True, exist_ok=True)
        self.add_nodes(1, extra_args=[[
            "-modelnet=1",
            "-modelbind=off",
            "-modelstorage=8MiB",
            f"-modelwatch={self.watch}",
            *MATMUL_OFF,
        ]])
        self.start_nodes()

    def skip_test_if_missing_module(self):
        self.skip_if_platform_not_posix()
        exeext = self.config["environment"].get("EXEEXT", "")
        builddir = self.config["environment"].get("BUILDDIR")
        if not builddir or not os.path.isfile(os.path.join(builddir, "bin", f"btx-modeld{exeext}")):
            if not os.environ.get("BTXMODELD"):
                raise SkipTest("btx-modeld not found")

    def run_test(self):
        node = self.nodes[0]
        self.wait_until(lambda: node.getmodelnetworkinfo().get("helper_ready"), timeout=60)
        before = node.getmodelnetworkinfo()
        restarts = before.get("helper_restart_count", 0)

        self.log.info("A header with a string dimension and one with a string offset")
        write_safetensors(self.watch / "bad-shape.safetensors",
                          {"t": {"dtype": "F32", "shape": ["x"], "data_offsets": [0, 4]}})
        write_safetensors(self.watch / "bad-offset.safetensors",
                          {"t": {"dtype": "F32", "shape": [1], "data_offsets": ["0", 4]}})
        time.sleep(3 * SCAN_S)
        after = node.getmodelnetworkinfo()
        assert_equal(after.get("helper_restart_count", 0), restarts)
        assert_equal(after.get("helper_ready"), True)
        if before.get("owner_helper_pid"):
            assert_equal(after.get("owner_helper_pid"), before.get("owner_helper_pid"))

        self.log.info("The scan goes on: a good file dropped next is hosted")
        write_safetensors(self.watch / "good.safetensors",
                          {"t": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]}})
        self.wait_until(lambda: len(node.listmodels().get("models", [])) >= 1, timeout=10 * SCAN_S)
        assert_equal(node.getmodelnetworkinfo().get("helper_restart_count", 0), restarts)


if __name__ == "__main__":
    ModelnetWatchBadHeaderTest(__file__).main()
