#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""A stuck model helper must not take every RPC worker of btxd.

Each model RPC that btxd forwards to btx-modeld holds an RPC worker until the
helper answers or the 120 s reply timeout ends. The test stops the node-owned
helper with SIGSTOP, sends more model RPCs than there are workers, and checks
that getblockcount still answers, that the calls over the limit fail at once
as busy, and that the helper serves calls again once it continues.
"""

import os
import signal
import threading
import time

from test_framework.authproxy import AuthServiceProxy
from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.util import assert_equal

RPC_THREADS = 4
CALLS = 6


class ModelnetHelperBusyTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def setup_nodes(self):
        modeld = os.path.join(self.config["environment"]["BUILDDIR"], "bin", "btx-modeld")
        if not os.path.isfile(modeld):
            raise SkipTest("btx-modeld not built")
        self.extra_args = [[f"-modelhelper={modeld}", "-modellandiscovery=0", f"-rpcthreads={RPC_THREADS}"]]
        super().setup_nodes()

    def run_test(self):
        node = self.nodes[0]
        self.wait_until(lambda: node.getmodelnetworkinfo().get("owner_helper_pid", 0) > 0, timeout=60)
        pid = node.getmodelnetworkinfo()["owner_helper_pid"]

        self.log.info("Stop the helper and send more model RPCs than there are RPC workers")
        os.kill(pid, signal.SIGSTOP)
        results = []

        def call():
            info = AuthServiceProxy(node.url, timeout=300).getmodelnetworkinfo()
            results.append(str(info.get("helper_error", "")))

        threads = [threading.Thread(target=call) for _ in range(CALLS)]
        try:
            for t in threads:
                t.start()
            time.sleep(2)
            self.log.info("getblockcount still answers")
            assert_equal(AuthServiceProxy(node.url, timeout=10).getblockcount(), 0)
            self.log.info("The calls over the limit fail at once as busy")
            self.wait_until(lambda: sum("busy" in err for err in results) == CALLS - RPC_THREADS // 2, timeout=10)
        finally:
            os.kill(pid, signal.SIGCONT)
        for t in threads:
            t.join(timeout=60)

        self.log.info("The helper serves calls again once it continues")
        info = node.getmodelnetworkinfo()
        assert_equal(info["helper_ready"], True)


if __name__ == '__main__':
    ModelnetHelperBusyTest(__file__).main()
