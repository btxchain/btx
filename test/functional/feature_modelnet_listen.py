#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""The model helper's PQ1 port follows -listen.

A node that does not listen (-listen=0, also set by -connect and -proxy)
starts its btx-modeld without a TCP listener, so the helper neither accepts
PQ1 connections nor asks a gateway to map its port. An explicit -modelbind
still wins. With -natpmp=0 a listening helper does not map its port either.
"""

import os
import socket
from pathlib import Path

from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.util import assert_equal, p2p_port

MATMUL_OFF_ARGS = [
    "-regtestmatmulbindingheight=2147483647",
    "-regtestmatmulproductdigestheight=2147483647",
    "-regtestmatmulv4height=2147483647",
    "-regtestmatmulrequireproductpayload=0",
]


class ModelNetListenTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        # -listen=0 refuses the harness's bind=127.0.0.1 config line.
        self.bind_to_localhost_only = False
        self.extra_args = [["-modelnet=0", *MATMUL_OFF_ARGS]]

    def skip_test_if_missing_module(self):
        self.skip_if_platform_not_posix()
        exeext = self.config["environment"].get("EXEEXT", "")
        modeld = Path(self.config["environment"]["BUILDDIR"]) / "bin" / f"btx-modeld{exeext}"
        if not (modeld.is_file() and os.access(modeld, os.X_OK)):
            raise SkipTest("btx-modeld missing")

    def helper_info(self):
        node = self.nodes[0]

        def ready():
            try:
                return node.getmodelnetworkinfo().get("helper_ready") is True
            except JSONRPCException:
                return False

        self.wait_until(ready, timeout=60)
        return node.getmodelnetworkinfo()

    def run_test(self):
        node = self.nodes[0]
        # btxd puts the helper's unix socket under the datadir. A deep tmpdir
        # pushes it past sun_path, and without XDG_RUNTIME_DIR btxd has
        # nowhere shorter to put it.
        sock = node.chain_path / "modelnet" / "modeld.sock"
        if len(str(sock).encode()) >= 104 and not os.environ.get("XDG_RUNTIME_DIR"):
            raise SkipTest(f"tmpdir too deep for the helper's unix socket ({sock})")
        args = ["-modelnet=1", "-modelstorage=0", *MATMUL_OFF_ARGS]

        self.log.info("-listen=0: the helper gets no PQ1 listener")
        with node.assert_debug_log(["parameter interaction: -listen=0 -> setting -modelbind=off",
                                    "storage=0 bind= host="]):
            self.restart_node(0, extra_args=[*args, "-listen=0"])
        assert_equal(self.helper_info()["nat_status"], "disabled")

        self.log.info("-listen=0 with an explicit -modelbind: the operator's address wins")
        port = p2p_port(1)
        bind = f"127.0.0.1:{port}"
        with node.assert_debug_log([f"bind={bind} host="],
                                   unexpected_msgs=["setting -modelbind=off"]):
            self.restart_node(0, extra_args=[*args, "-listen=0", f"-modelbind={bind}"])
        self.helper_info()
        socket.create_connection(("127.0.0.1", port), timeout=10).close()

        self.log.info("-natpmp=0: a listening helper does not try to map its port")
        # BTX_MODEL_PCP_LAB lets the helper try to map a loopback bind, and
        # BTX_MODEL_PCP_GATEWAY sends any request to a local address that
        # nobody answers, so this step stays on loopback and never talks to
        # the real default gateway. Without the fix the helper tries anyway
        # and reports "unmapped".
        bind = f"127.0.0.1:{p2p_port(2)}"
        self.stop_node(0)
        with node.assert_debug_log([f"bind={bind} host="]):
            self.start_node(0, extra_args=[*args, "-natpmp=0", f"-modelbind={bind}"],
                            env={"BTX_MODEL_PCP_LAB": "1", "BTX_MODEL_PCP_GATEWAY": "127.0.0.1"})
        assert_equal(self.helper_info()["nat_status"], "disabled")


if __name__ == '__main__':
    ModelNetListenTest(__file__).main()
