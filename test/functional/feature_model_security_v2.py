#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers. MIT license.
"""Real-daemon security guard lifecycle checks. No synthetic PASS receipts.

This test requires the integrated btxd, btx-modeld and btx-guardd binaries.
It is not a physical multi-host, real-model or GPU qualification.
"""
import os

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class ModelSecurityV2Test(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        # Do not force -modelnet=1: exercise the product default.
        self.extra_args = [[]]

    def run_test(self):
        node = self.nodes[0]

        def ready():
            try:
                return node.modelsecurity({"op": "status"}).get("ok") is True
            except Exception:
                return False

        self.wait_until(ready, timeout=30)
        first = node.modelsecurity({"op": "status"})
        assert_equal(first["policy_installed"], False)
        assert_equal(first["automatic_spend_atoms"], "0")
        assert_equal(first["model_safety_proven"], False)
        assert_equal(first["legacy_generatemodel_mediated"], False)
        assert_equal(first["general_gpu_runtime_qualified"], False)
        assert_equal(first["continuous_protection_required"], False)
        mesh = first["multi_host_security"]
        assert_equal(mesh["enabled"], False)
        assert_equal(mesh["qualified_production"], False)
        assert_equal(mesh["physical_host_independence_proven"], False)
        assert_equal(first["journal_valid"], True)
        assert_equal(node.modelsecurity({"op": "arbitrary-shell", "command": "not executed"})["ok"], False)
        assert_equal(node.modelsecurity({"op": "pause"})["ok"], True)
        assert_equal(node.modelsecurity({"op": "status"})["paused"], True)
        height = node.getblockcount()
        # Model authority failure must not take down monetary RPC.
        assert_equal(node.getblockcount(), height)
        self.restart_node(0)
        self.wait_until(ready, timeout=30)
        second = node.modelsecurity({"op": "status"})
        assert first["guard_boot"] != second["guard_boot"]
        assert_equal(second["paused"], True)
        assert_equal(second["journal_valid"], True)
        assert_equal(node.getblockcount(), height)

        if os.name == "posix":
            self.symlinked_datadir(node, first, height, ready)

    def symlinked_datadir(self, node, first, height, ready):
        # A datadir moved to another disk behind a symlink (~/.btx ->
        # /mnt/ssd/btx; feature_dirsymlinks.py does this for blocks and
        # chainstate) must keep the guard and btx-modeld's security gate up.
        self.stop_node(0)
        datadir = node.datadir_path
        moved = datadir.parent / (datadir.name + "-on-other-disk")
        os.rename(datadir, moved)
        os.symlink(moved, datadir)
        assert os.path.islink(datadir) and os.path.isdir(datadir)
        self.start_node(0)
        self.wait_until(ready, timeout=30)
        third = node.modelsecurity({"op": "status"})
        assert first["guard_boot"] != third["guard_boot"]
        assert_equal(third["paused"], True)
        assert_equal(third["journal_valid"], True)
        assert_equal(node.getblockcount(), height)
        # With root pins present, btx-modeld opens the same store for its
        # loadmodel/generatemodel gate: an unknown id is NOT_FOUND, not
        # SEC_PROTECTION_STATE_UNAVAILABLE.
        pins = node.chain_path / "modelnet" / "security" / "root-pins.json"
        fd = os.open(pins, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf8") as f:
            f.write('{"keys":["' + "ab" * 48 + '"],"schema":"BTX/SecurityRootPins/v1","threshold":1}\n')
        self.wait_until(lambda: node.getmodelnetworkinfo()["helper_ready"] is True, timeout=30)
        assert_raises_rpc_error(-8, "NOT_FOUND", node.loadmodel, "11" * 48)
        assert_raises_rpc_error(-8, "NOT_FOUND", node.generatemodel, "11" * 48, {"prompt": "x"})


if __name__ == "__main__":
    ModelSecurityV2Test(__file__).main()
