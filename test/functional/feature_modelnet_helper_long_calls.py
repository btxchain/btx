#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""A long helper call must not take the helper's last free unix worker.

btx-modeld serves unix RPC with two workers, and waitformodelevent holds its
worker until an event arrives or its timeout ends. With one event wait
running, a second long call must be refused at once as busy, a short call
must still answer, and the slot must be free again once the first wait ends.
"""

import os
import threading

from test_framework.authproxy import AuthServiceProxy
from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.util import assert_equal, assert_raises_rpc_error

NO_EVENT_CURSOR = 1 << 60
WAIT_MS = 15000


class ModelnetHelperLongCallsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def setup_nodes(self):
        modeld = os.path.join(self.config["environment"]["BUILDDIR"], "bin", "btx-modeld")
        if not os.path.isfile(modeld):
            raise SkipTest("btx-modeld not built")
        self.extra_args = [[f"-modelhelper={modeld}", "-modellandiscovery=0"]]
        super().setup_nodes()

    def run_test(self):
        node = self.nodes[0]
        self.wait_until(lambda: node.getmodelnetworkinfo().get("owner_helper_pid", 0) > 0, timeout=60)

        self.log.info("Start one event wait")
        first = {}

        def wait_for_event():
            proxy = AuthServiceProxy(node.url, timeout=WAIT_MS // 1000 + 60)
            first["result"] = proxy.waitformodelevent({"cursor": NO_EVENT_CURSOR, "timeout_ms": WAIT_MS})

        waiter = threading.Thread(target=wait_for_event)
        waiter.start()
        self.wait_until(lambda: "waitformodelevent" in str(node.getrpcinfo()["active_commands"]), timeout=10)

        self.log.info("A second long call is refused at once")
        assert_raises_rpc_error(-8, "HELPER_BUSY", AuthServiceProxy(node.url, timeout=10).waitformodelevent,
                                {"cursor": NO_EVENT_CURSOR, "timeout_ms": WAIT_MS})

        self.log.info("A short call still answers")
        AuthServiceProxy(node.url, timeout=10).checkmodelsetup()

        self.log.info("The first wait ends normally and frees its slot")
        waiter.join(timeout=WAIT_MS // 1000 + 60)
        assert_equal(first["result"]["timeout"], True)
        node.waitformodelevent({"cursor": NO_EVENT_CURSOR, "timeout_ms": 0})


if __name__ == '__main__':
    ModelnetHelperLongCallsTest(__file__).main()
