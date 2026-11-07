#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""A killed btxd must not leave its model helper holding its ports.

btxd starts btx-modeld after it has bound its P2P port. After a kill -9 of
btxd a restarted btxd must bind that port again, the old helper must exit on
its own, and the new btxd must start a helper it manages.
"""
import os
from pathlib import Path

from test_framework.test_framework import BitcoinTestFramework, SkipTest


def alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


class ModelHelperAfterKillTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [["-modelnet=1"]]

    def skip_test_if_missing_module(self):
        self.skip_if_platform_not_posix()
        if not (Path(self.options.bitcoind).resolve().parent / "btx-modeld").exists():
            raise SkipTest("btx-modeld is not next to btxd")

    def managed_helper(self, node):
        info = node.getmodelnetworkinfo()
        if info["helper_managed_by_btxd"] and info["helper_pid"] > 0:
            return info["helper_pid"]
        return None

    def run_test(self):
        node = self.nodes[0]
        self.wait_until(lambda: self.managed_helper(node) is not None, timeout=60)
        old_pid = self.managed_helper(node)

        self.log.info("After a kill -9 of btxd, a restart binds the P2P port again")
        node.kill_process()
        self.start_node(0)

        self.log.info("The old helper exits on its own and the new btxd manages a new one")
        self.wait_until(lambda: not alive(old_pid), timeout=30)
        self.wait_until(lambda: self.managed_helper(node) not in (None, old_pid), timeout=60)


if __name__ == '__main__':
    ModelHelperAfterKillTest(__file__).main()
