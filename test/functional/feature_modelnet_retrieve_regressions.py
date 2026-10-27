#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Regression tests for the model-plane fixes reported in #228, #229, #230, #232.

Loopback helpers and one regtest btxd only. CPU only. Nothing spends.

- #228: a helper whose PATH holds no ML-DSA-capable `openssl` CLI (and with
  BTX_OPENSSL unset) still starts, reaches PQ1, and writes tls/cert.pem and
  tls/key.pem with mode 0600. 0.34.15 exited 2 here ("openssl mldsa44
  certificate generation failed").
- #229: two hosts serve the same model and the fetcher is told about both.
  0.34.15 let the second host's FreeGrant replace the first's, and the fetch
  failed with 403 "grant identity".
- #230: a host with -modeluploadlimit serves a whole fetch, paced at its cap.
  0.34.15 refused with 429 and the fetch failed ("missing FreeGrant").
- #232: removemodel through btxd deletes the pieces and the checkout, and
  `btx-model rm` does the same through the helper socket. `btx-model rm`
  refuses a name that two local models share.

--cases picks a subset (default: all). Run with the configfile of an older
build to see what each case locks in.
"""

import hashlib
import json
import os
import shutil
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.util import assert_equal, p2p_port

PIECE_SIZE = 4 << 20  # src/modelnet/types.h
SWARM_BYTES = 64 << 20  # #229: 17 pieces, so the fetcher asks both hosts
PACED_BYTES = 16 << 20  # #230: about 10 s at the cap below
UPLOAD_LIMIT = "2MiB"
UPLOAD_LIMIT_BPS = 2 << 20
REMOVE_BYTES = 8 << 20
ALL_CASES = ("228", "229", "230", "232")

# Where OpensslBin() (src/modelnet/pq1_runtime.cpp) looks before PATH.
FIXED_OPENSSL_PATHS = (
    "/opt/openssl-3.5.8/bin/openssl",
    "/opt/homebrew/opt/openssl@3/bin/openssl",
    "/opt/homebrew/opt/openssl/bin/openssl",
    "/usr/local/opt/openssl@3/bin/openssl",
    "/usr/local/opt/openssl/bin/openssl",
)


class ModelNetRetrieveRegressionsTest(BitcoinTestFramework):
    def add_options(self, parser):
        parser.add_argument("--cases", default=",".join(ALL_CASES),
                            help="comma list of issue numbers to run (default: all)")

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.helpers = {}
        self.sock_scratch = None

    def skip_test_if_missing_module(self):
        self.skip_if_platform_not_posix()
        if self._modeld() is None:
            raise SkipTest("btx-modeld missing")

    def setup_network(self):
        # btxd starts only in the #232 case, after its helper is up.
        self.add_nodes(self.num_nodes)

    def shutdown(self):
        for name in list(self.helpers):
            self._stop_helper(name)
        if self.sock_scratch is not None:
            shutil.rmtree(self.sock_scratch, ignore_errors=True)
        return super().shutdown()

    # ---------- helpers (scratch btx-modeld processes) ----------

    def _modeld(self):
        env = self.config["environment"]
        cand = Path(env["BUILDDIR"]) / "bin" / f"btx-modeld{env.get('EXEEXT', '')}"
        return cand if cand.is_file() and os.access(cand, os.X_OK) else None

    def _sock_path(self, name):
        base = Path(self.options.tmpdir) / "s"
        if len(str(base / f"{name}.sock")) > 100:  # AF_UNIX sun_path is 108 bytes
            if self.sock_scratch is None:
                self.sock_scratch = Path(tempfile.mkdtemp(prefix="btxrr-"))
            base = self.sock_scratch
        base.mkdir(parents=True, exist_ok=True)
        return base / f"{name}.sock"

    def _start_helper(self, name, args, env=None, storage="512MiB"):
        modeldir = Path(self.options.tmpdir) / f"modeldir-{name}"
        modeldir.mkdir(parents=True, exist_ok=True)
        sock = self._sock_path(name)
        if sock.exists():
            sock.unlink()
        argv = [str(self._modeld()), f"-modeldir={modeldir}", f"-modelrpcsocket={sock}",
                f"-modelstorage={storage}", "-modelfollowpeers=0", *args]
        log = open(modeldir / "modeld.log", "w", encoding="utf-8")
        self.log.info("helper %s: %s", name, " ".join(argv[1:]))
        proc = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT, cwd=str(modeldir), env=env)
        self.helpers[name] = {"proc": proc, "log": log, "dir": modeldir, "sock": sock}
        return self._wait_ready(name)

    def _host(self, name, port, extra=()):
        return self._start_helper(name, [f"-modelbind=127.0.0.1:{port}", "-modelhost", *extra])

    def _fetcher(self, name, ports):
        return self._start_helper(name, [f"-modelpeer=127.0.0.1:{p}" for p in ports])

    def _stop_helper(self, name):
        h = self.helpers.pop(name, None)
        if h is None:
            return
        if h["proc"].poll() is None:
            h["proc"].terminate()
            try:
                h["proc"].wait(timeout=30 * self.options.timeout_factor)
            except subprocess.TimeoutExpired:
                h["proc"].kill()  # a scratch helper this test started
                h["proc"].wait(timeout=10)
        h["log"].close()

    def _tail(self, name, n=1500):
        log = Path(self.options.tmpdir) / f"modeldir-{name}" / "modeld.log"
        return log.read_text(encoding="utf-8", errors="replace")[-n:] if log.exists() else ""

    def _rpc(self, name, method, params=None):
        h = self.helpers[name]
        if h["proc"].poll() is not None:
            raise AssertionError(f"helper {name} exited rc={h['proc'].returncode}\n{self._tail(name)}")
        wire = (json.dumps({"jsonrpc": "1.0", "id": "rr", "method": method,
                            "params": params or []}) + "\n").encode()
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.settimeout(120 * self.options.timeout_factor)
        try:
            client.connect(str(h["sock"]))
            client.sendall(wire)
            client.shutdown(socket.SHUT_WR)
            buf = b""
            while b"\n" not in buf:
                chunk = client.recv(65536)
                if not chunk:
                    break
                buf += chunk
        finally:
            client.close()
        reply = json.loads(buf.split(b"\n", 1)[0])
        if reply.get("error") not in (None, {}):
            raise AssertionError(f"{name} {method}: {reply['error']}")
        result = reply.get("result")
        if isinstance(result, dict):
            assert_equal(int(result.get("automatic_spend_atoms", 0)), 0)
        return result

    def _wait_ready(self, name):
        deadline = time.time() + 60 * self.options.timeout_factor
        last = None
        while time.time() < deadline:
            proc = self.helpers[name]["proc"]
            if proc.poll() is not None:
                raise AssertionError(f"helper {name} exited rc={proc.returncode}\n{self._tail(name)}")
            try:
                info = self._rpc(name, "getmodelnetworkinfo")
                if info.get("helper_ready"):
                    if not info.get("pq1_ready"):
                        raise AssertionError(f"helper {name} is up without PQ1: {info}")
                    return info
                last = info
            except (OSError, ValueError) as e:
                last = e
            time.sleep(0.2)
        raise AssertionError(f"helper {name} not ready: {last}\n{self._tail(name)}")

    # ---------- models ----------

    def _write_model(self, tag, size):
        path = Path(self.options.tmpdir) / f"src-{tag}" / "model.safetensors"
        path.parent.mkdir(parents=True, exist_ok=True)
        header = json.dumps({"t": {"dtype": "U8", "shape": [size], "data_offsets": [0, size]}},
                            separators=(",", ":")).encode()
        path.write_bytes(struct.pack("<Q", len(header)) + header + hashlib.shake_256(tag.encode()).digest(size))
        return path

    def _import(self, name, path):
        imported = self._rpc(name, "importmodel", [str(path), {"pin": True}])
        assert imported.get("uri"), imported
        return imported

    def _fetch(self, name, uri):
        """getmodel FREE_ONLY on a fetcher helper; returns (job, seconds)."""
        t0 = time.time()
        got = self._rpc(name, "getmodel", [uri, "FREE_ONLY"])
        job = got
        job_id = got.get("job_id")
        deadline = t0 + 240 * self.options.timeout_factor
        while job_id and time.time() < deadline:
            raw = self._rpc(name, "getmodeljob", [job_id])
            if isinstance(raw, dict) and raw.get("jobs") is not None:
                raw = next((j for j in raw["jobs"] if str(j.get("job_id")) == str(job_id)), {})
            job = raw or {}
            if job.get("status") in ("done", "failed", "cancelled"):
                break
            time.sleep(0.25)
        elapsed = time.time() - t0
        result = job.get("result") or job
        if (job_id and job.get("status") != "done") or result.get("status") not in ("retrieved", "local"):
            raise AssertionError(f"{name} fetch did not complete after {elapsed:.1f}s: {job}\n{self._tail(name)}")
        return job, elapsed

    def _assert_bytes_match(self, name, uri):
        man = self._rpc(name, "getmodelmanifest", [uri])
        assert man.get("complete") is True, man
        (entry,) = man["files"]
        digest = hashlib.sha384()
        pieces = Path(self.helpers[name]["dir"]) / "store" / "artifacts" / man["artifact_id"] / "0"
        n = (int(entry["size"]) + PIECE_SIZE - 1) // PIECE_SIZE
        for i in range(n):
            digest.update((pieces / f"{i}.piece").read_bytes())
        assert_equal(digest.hexdigest(), entry["sha384"])

    # ---------- cases ----------

    def run_test(self):
        cases = [c.strip().lstrip("#") for c in self.options.cases.split(",") if c.strip()]
        unknown = set(cases) - set(ALL_CASES)
        if unknown:
            raise AssertionError(f"unknown --cases {sorted(unknown)}; known: {ALL_CASES}")
        for case in cases:
            self.log.info("---- #%s ----", case)
            getattr(self, f"case_{case}")()

    @staticmethod
    def _openssl_does_mldsa(exe):
        try:
            run = subprocess.run([str(exe), "list", "-signature-algorithms"], capture_output=True,
                                 text=True, timeout=30)
        except (OSError, subprocess.TimeoutExpired):
            return False
        return "ML-DSA-44" in run.stdout

    def case_228(self):
        self.log.info("#228: the helper mints its ML-DSA TLS identity without an ML-DSA openssl CLI")
        # Drop every PATH entry whose openssl can make ML-DSA keys. An older
        # CLI (OpenSSL 3.0, LibreSSL) may stay, as on a stock Mac.
        keep, dropped = [], []
        for d in os.environ.get("PATH", "").split(os.pathsep):
            exe = Path(d) / "openssl"
            capable = bool(d) and exe.is_file() and os.access(exe, os.X_OK) and self._openssl_does_mldsa(exe)
            (dropped if capable else keep).append(d)
        env = {k: v for k, v in os.environ.items() if k not in ("BTX_OPENSSL", "OPENSSL_CONF", "OPENSSL_MODULES")}
        env["PATH"] = os.pathsep.join(keep)
        self.log.info("PATH without an ML-DSA openssl (dropped %s): %s", dropped, env["PATH"])
        for path in FIXED_OPENSSL_PATHS:
            if os.access(path, os.X_OK):
                self.log.info("note: %s exists, so a build that still runs the CLI would find it here", path)
        self._start_helper("tls", [], env=env, storage="0")
        tls = self.helpers["tls"]["dir"] / "tls"
        for f, header in (("cert.pem", "-----BEGIN CERTIFICATE-----"), ("key.pem", "-----BEGIN PRIVATE KEY-----")):
            path = tls / f
            assert path.is_file(), f"missing {path}"
            assert_equal(oct(stat.S_IMODE(path.stat().st_mode)), "0o600")
            assert path.read_text(encoding="ascii").startswith(header), path
        self._stop_helper("tls")

    def case_229(self):
        self.log.info("#229: a fetch told about two hosts with the same model completes")
        src = self._write_model("two-hosts", SWARM_BYTES)
        ports = [p2p_port(1), p2p_port(2)]
        self._host("h1", ports[0])
        self._host("h2", ports[1])
        uris = {self._import(h, src)["uri"] for h in ("h1", "h2")}
        assert_equal(len(uris), 1)
        uri = uris.pop()
        self._fetcher("f2", ports)
        peers = json.dumps(self._rpc("f2", "getmodelpeers").get("peers"))
        assert all(f"127.0.0.1:{p}" in peers for p in ports), peers
        job, secs = self._fetch("f2", uri)
        self._assert_bytes_match("f2", uri)
        self.log.info("two-host fetch done in %.1fs, peer_retries=%s", secs, job.get("peer_retries"))
        for name in ("f2", "h1", "h2"):
            self._stop_helper(name)

    def case_230(self):
        self.log.info("#230: a host under -modeluploadlimit=%s serves a whole fetch", UPLOAD_LIMIT)
        src = self._write_model("paced", PACED_BYTES)
        port = p2p_port(3)
        self._host("hp", port, [f"-modeluploadlimit={UPLOAD_LIMIT}"])
        uri = self._import("hp", src)["uri"]
        self._fetcher("fp", [port])
        _, secs = self._fetch("fp", uri)
        self._assert_bytes_match("fp", uri)
        rate = PACED_BYTES / secs
        self.log.info("paced fetch done in %.1fs, %.2f MiB/s", secs, rate / (1 << 20))
        # The cap holds: well under the unpaced loopback rate. The margin covers
        # the governor's burst at the start of a short transfer.
        assert rate <= 1.5 * UPLOAD_LIMIT_BPS, f"{rate:.0f} B/s is over the {UPLOAD_LIMIT} cap"
        for name in ("fp", "hp"):
            self._stop_helper(name)

    def case_232(self):
        self.log.info("#232: removemodel through btxd and `btx-model rm` free the model's bytes")
        self._start_helper("rm", [], storage="64MiB")
        node = self.nodes[0]
        self.start_node(0, extra_args=["-modelnet=1", f"-modelrpcsocket={self.helpers['rm']['sock']}"])
        self.wait_until(lambda: node.getmodelnetworkinfo().get("helper_ready"))
        modeldir = self.helpers["rm"]["dir"]

        imported = node.importmodel(str(self._write_model("remove-a", REMOVE_BYTES)), {"pin": True})
        model_id = imported["model_id"]
        artifact = node.getmodelmanifest(imported["uri"])["artifact_id"]
        checkout = Path(node.exportmodelpath(imported["uri"])["path"])
        assert checkout.is_dir(), checkout
        assert list((modeldir / "store").rglob("*.piece")), "import wrote no pieces"

        removed = node.removemodel(model_id)
        assert_equal(removed["removed"], True)
        assert_equal(removed["checkout_removed"], True)
        assert_equal(removed["automatic_spend_atoms"], 0)
        assert not checkout.exists(), checkout
        assert not (modeldir / "store" / "artifacts" / artifact).exists()
        assert_equal(list((modeldir / "store").rglob("*.piece")), [])
        assert model_id not in [m.get("model_id") for m in node.listmodels().get("models", [])]

        cli = Path(self.config["environment"]["SRCDIR"]) / "contrib" / "modelnet" / "btx-model"
        env = {k: v for k, v in os.environ.items() if k not in ("MODELD_SOCK", "BTX_MODELD_SOCKET")}

        def btx_model_rm(ref):
            run = subprocess.run([sys.executable, str(cli), "--socket", str(self.helpers["rm"]["sock"]), "--json",
                                  "rm", ref], capture_output=True, text=True, env=env,
                                 timeout=60 * self.options.timeout_factor)
            return run.returncode, json.loads(run.stdout)

        second = self._import("rm", self._write_model("remove-b", REMOVE_BYTES))
        third = self._import("rm", self._write_model("remove-c", REMOVE_BYTES))
        # Both files are model.safetensors, so both models have that name: rm
        # refuses to pick one and deletes nothing.
        rc, out = btx_model_rm("model.safetensors")
        assert_equal(rc, 1)
        assert "2 local models match" in out.get("error", ""), out
        assert_equal(len(self._rpc("rm", "listmodels").get("models") or []), 2)

        checkout_b = Path(self._rpc("rm", "exportmodelpath", [second["uri"]])["path"])
        assert checkout_b.is_dir(), checkout_b
        rc, out = btx_model_rm(second["model_id"])
        assert_equal(rc, 0)
        assert_equal(out.get("removed"), True)
        assert_equal(out.get("checkout_removed"), True)
        assert not checkout_b.exists(), checkout_b

        # One model has the name now, so rm by name deletes that one.
        rc, out = btx_model_rm("model.safetensors")
        assert_equal(rc, 0)
        assert_equal(out.get("model_id"), third["model_id"])
        assert_equal(list((modeldir / "store").rglob("*.piece")), [])
        assert_equal(self._rpc("rm", "listmodels").get("models") or [], [])
        self.stop_node(0)
        self._stop_helper("rm")


if __name__ == "__main__":
    ModelNetRetrieveRegressionsTest(__file__).main()
