#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""A .btx card in the watch folder must not hold up the helper.

The watch scan opens a dropped share card with getmodel FREE_ONLY. getmodel
queues a retrieve job when it has the helper's stop flag and otherwise
downloads in the calling thread. The automatic -modelwatch scan runs in the
helper's accept loop, so a card for a model that is not local must queue a
job there too, or every helper RPC waits for the peers.

The only model-plane peer here accepts TCP on 127.0.0.1 and never answers.
"""

import json
import os
import socket
import struct
import threading
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
# A helper RPC answers in milliseconds; one silent peer held it for 10 s.
SLOW_S = 5


def write_safetensors(path, tag):
    hdr = json.dumps({
        "__metadata__": {"format": "pt", "tag": tag},
        "w": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]},
    }).encode()
    with open(path, "wb") as f:
        f.write(struct.pack("<Q", len(hdr)) + hdr + b"\0\0\0\0")


class SilentPeer:
    """Accepts TCP connections and never sends a byte."""

    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self.conns = []
        self.done = False
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self):
        while not self.done:
            try:
                conn, _ = self.sock.accept()
                self.conns.append(conn)
            except OSError:
                pass

    def close(self):
        self.done = True
        self.thread.join(timeout=5)
        for conn in self.conns:
            conn.close()
        self.sock.close()


class ModelnetWatchCardRetrieveTest(BitcoinTestFramework):
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

    def absent_model(self, node, tag):
        """Host a model, then remove it, so that only its card is left."""
        model_dir = Path(node.datadir_path) / f"model-{tag}"
        model_dir.mkdir(parents=True, exist_ok=True)
        write_safetensors(model_dir / "toy.safetensors", tag)
        hosted = node.hostmodel(str(model_dir))
        node.removemodel(hosted["uri"])
        return hosted["uri"]

    def timed_call(self, node):
        start = time.monotonic()
        node.getmodelnetworkinfo()
        return time.monotonic() - start

    def run_test(self):
        node = self.nodes[0]
        self.wait_until(lambda: node.getmodelnetworkinfo().get("helper_ready"), timeout=30)
        peer = SilentPeer()
        assert_equal(node.addmodelnode(f"127.0.0.1:{peer.port}")["ok"], True)

        self.log.info("scanmodelwatch queues a retrieve job for a dropped card")
        uri = self.absent_model(node, "rpc")
        drop = Path(self.options.tmpdir) / "drop"
        drop.mkdir()
        (drop / "rpc.btx").write_text(uri + "\n", encoding="utf8")
        start = time.monotonic()
        scanned = node.scanmodelwatch(str(drop))
        took = time.monotonic() - start
        assert_equal(len(scanned["opened"]), 1)
        retrieve = scanned["opened"][0]["retrieve"]
        assert_equal(retrieve.get("async"), True)
        assert retrieve.get("job_id"), retrieve
        assert took < SLOW_S, f"scanmodelwatch waited {took:.1f} s for the peer"
        node.cancelmodeljob(retrieve["job_id"])

        self.log.info("the automatic -modelwatch scan does not hold up helper RPCs")
        uri = self.absent_model(node, "auto")
        jobs_before = {job["job_id"] for job in node.getmodeljob()["jobs"]}
        # Write the card under a name the scan skips, then rename it, so that
        # the scan never reads a half-written card.
        tmp = self.watch / "auto.btx.tmp"
        tmp.write_text(uri + "\n", encoding="utf8")
        os.replace(tmp, self.watch / "auto.btx")
        slowest = 0.0
        new_jobs = set()
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            slowest = max(slowest, self.timed_call(node))
            new_jobs |= {job["job_id"] for job in node.getmodeljob()["jobs"]} - jobs_before
            time.sleep(0.2)
        assert slowest < SLOW_S, f"a helper RPC waited {slowest:.1f} s while the watch scan opened the card"
        assert new_jobs, "the watch scan queued no retrieve job for the card"
        for job_id in new_jobs:
            node.cancelmodeljob(job_id)
        peer.close()


if __name__ == "__main__":
    ModelnetWatchCardRetrieveTest(__file__).main()
