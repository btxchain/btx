#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""A campaigns.json that cannot be read must not free a funding release.

A model with a release that is still being funded is not seeded as
plaintext. The helper keeps that release in campaigns.json. When the file,
or the entry of a local release in it, cannot be read after a restart, the
helper must keep withholding the plaintext and must not overwrite the file.
"""

import json
import os
import struct
import subprocess
from pathlib import Path

from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.util import assert_raises_rpc_error, get_datadir_path

MATMUL_OFF_ARGS = [
    "-regtestmatmulbindingheight=2147483647",
    "-regtestmatmulproductdigestheight=2147483647",
    "-regtestmatmulv4height=2147483647",
    "-regtestmatmulrequireproductpayload=0",
]


def write_minimal_safetensors(path, tag):
    path.parent.mkdir(parents=True, exist_ok=True)
    header = json.dumps({"__metadata__": {"tag": tag}}).encode()
    path.write_bytes(struct.pack("<Q", len(header)) + header)


class ModelNetCampaignsUnreadableTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.modeld_proc = None
        self.modeld_log = None

    def skip_test_if_missing_module(self):
        self.skip_if_platform_not_posix()
        if self.modeld_path() is None:
            raise SkipTest("btx-modeld not found")

    def modeld_path(self):
        name = "btx-modeld" + self.config["environment"].get("EXEEXT", "")
        candidates = [Path(os.environ[v]) for v in ("BTXMODELD", "BTX_MODELD") if os.environ.get(v)]
        builddir = self.config["environment"].get("BUILDDIR")
        if builddir:
            candidates.append(Path(builddir) / "bin" / name)
        for cand in candidates:
            if cand.is_file() and os.access(cand, os.X_OK):
                return cand
        return None

    def start_helper(self):
        datadir = Path(get_datadir_path(self.options.tmpdir, 0))
        datadir.mkdir(parents=True, exist_ok=True)
        self.modeldir = datadir / "md"
        self.modeldir.mkdir(parents=True, exist_ok=True)
        self.modeld_socket = self.modeldir / "m.sock"
        if self.modeld_socket.exists():
            self.modeld_socket.unlink()
        self.modeld_log = open(self.modeldir / "modeld.log", "a", encoding="utf-8")
        self.modeld_proc = subprocess.Popen(
            [str(self.modeld_path()), f"-modeldir={self.modeldir}", "-modelstorage=8MiB",
             f"-modelrpcsocket={self.modeld_socket}"],
            stdout=self.modeld_log, stderr=subprocess.STDOUT, cwd=str(datadir))

    def stop_helper(self):
        proc, self.modeld_proc = self.modeld_proc, None
        if proc is not None and proc.poll() is None:
            proc.terminate()
            proc.wait(timeout=60)
        if self.modeld_log is not None:
            self.modeld_log.close()
            self.modeld_log = None

    def wait_helper(self):
        def ready():
            assert self.modeld_proc.poll() is None, "btx-modeld exited"
            try:
                self.nodes[0].listmodels()
                return True
            except JSONRPCException:
                return False
        self.wait_until(ready, timeout=60)

    def restart_helper(self):
        self.stop_helper()
        self.start_helper()
        self.wait_helper()

    def setup_nodes(self):
        self.start_helper()
        self.add_nodes(1, extra_args=[["-modelnet=1", f"-modelrpcsocket={self.modeld_socket}", *MATMUL_OFF_ARGS]])
        self.start_nodes()

    def shutdown(self):
        self.stop_helper()
        return super().shutdown()

    def campaigns_file(self):
        found = sorted(self.modeldir.rglob("campaigns.json"))
        assert len(found) == 1, found
        return found[0]

    def run_test(self):
        node = self.nodes[0]
        self.wait_helper()

        self.log.info("A hosted model with a release that is still funding is not seeded as plaintext")
        src = Path(self.options.tmpdir) / "src" / "model.safetensors"
        write_minimal_safetensors(src, "campaigns-unreadable")
        hosted = node.hostmodel(str(src))
        uri = hosted.get("uri") or hosted.get("model_id")
        node.createmodelrelease({"uri": uri, "secret32_hex": "a" * 64, "refund_height": 100000})
        assert_raises_rpc_error(-8, "NOT_DOWNLOADABLE", node.seedmodel, uri)
        path = self.campaigns_file()
        good = path.read_bytes()
        campaigns = json.loads(good)["campaigns"]
        assert len(campaigns) == 1

        self.log.info("campaigns.json cut short: the plaintext stays withheld and the file is kept")
        self.stop_helper()
        path.write_bytes(good[: len(good) // 2])
        damaged = path.read_bytes()
        self.start_helper()
        self.wait_helper()
        assert_raises_rpc_error(-8, "NOT_DOWNLOADABLE", node.seedmodel, uri)
        other = Path(self.options.tmpdir) / "src2" / "model.safetensors"
        write_minimal_safetensors(other, "campaigns-unreadable-2")
        other_hosted = node.hostmodel(str(other))
        other_uri = other_hosted.get("uri") or other_hosted.get("model_id")
        try:
            node.createmodelrelease({"uri": other_uri, "secret32_hex": "b" * 64, "refund_height": 100000})
        except JSONRPCException:
            pass
        assert_raises_rpc_error(-8, "NOT_DOWNLOADABLE", node.seedmodel, uri)
        assert path.read_bytes() == damaged, "campaigns.json was overwritten"

        self.log.info("The entry of the local release cannot be read: the plaintext stays withheld")
        self.stop_helper()
        bad = json.loads(good)
        bad["campaigns"][0]["target_atoms"] = "not a number"
        path.write_text(json.dumps(bad))
        self.start_helper()
        self.wait_helper()
        assert_raises_rpc_error(-8, "NOT_DOWNLOADABLE", node.seedmodel, uri)

        self.log.info("Repaired file: the release is back and still withholds the plaintext")
        self.stop_helper()
        path.write_bytes(good)
        self.start_helper()
        self.wait_helper()
        assert_raises_rpc_error(-8, "NOT_DOWNLOADABLE", node.seedmodel, uri)
        assert len(json.loads(self.campaigns_file().read_bytes())["campaigns"]) >= 1


if __name__ == "__main__":
    ModelNetCampaignsUnreadableTest(__file__).main()
