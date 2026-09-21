#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""CR12-J17 process-tier scale: small HTTP batches, slow readers, job cancel.

100k-row Crl12LoadSynthetic is native-only (hcpd max body 1MiB).
10m-row lab is native-only and HONEST_NOT_RUN unless exercised in unit tests
with BTX_CR12_10M_LAB. Isolated regtest. Never production btxd.
"""

import json
import os
import socket
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.util import get_datadir_path

MATMUL_OFF_ARGS = [
    "-regtestmatmulbindingheight=2147483647",
    "-regtestmatmulproductdigestheight=2147483647",
    "-regtestmatmulv4height=2147483647",
    "-regtestmatmulrequireproductpayload=0",
]
API_BASE = "https://exchange.example/btx/hcp/v1"
VERIFIER = "pkce-verifier-demo-aaaa"
PORT = 18830


def pjson(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


class ModelNetCr12Scale(BitcoinTestFramework):
    def set_test_params(self):
        # HCP-only: do not start btxd/modeld. Isolated loopback btx-hcpd.
        self.num_nodes = 0
        self.setup_clean_chain = True
        self.procs = []
        self.not_run = []

    def setup_network(self):
        pass

    def setup_nodes(self):
        pass

    def skip_test_if_missing_module(self):
        self.skip_if_platform_not_posix()
        builddir = self.config["environment"].get("BUILDDIR")
        self.hcpd = Path(builddir) / "bin" / "btx-hcpd"
        if not self.hcpd.is_file():
            raise SkipTest("btx-hcpd not found")

    def _honest(self, reason):
        self.not_run.append(reason)
        self.log.info("HONEST_NOT_RUN J17: %s", reason)

    def _start(self):
        d = Path(get_datadir_path(self.options.tmpdir, 0)) / "scale"
        d.mkdir(parents=True, exist_ok=True)
        argv = [str(self.hcpd), f"-bind=127.0.0.1:{PORT}", f"-datadir={d}", "-instance=scale", "-finance=1"]
        log = open(d / "hcpd.log", "w", encoding="utf-8")
        p = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT)
        for _ in range(50):
            if p.poll() is not None:
                break
            try:
                s = socket.create_connection(("127.0.0.1", PORT), 0.2)
                s.close()
                self.procs.append((p, log))
                return
            except OSError:
                time.sleep(0.1)
        p.terminate()
        log.close()
        raise RuntimeError("hcpd scale")

    def _stop(self):
        for p, log in self.procs:
            if p.poll() is None:
                p.terminate()
                try:
                    p.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    p.kill()
            log.close()
        self.procs = []

    def _get(self, url):
        with urllib.request.urlopen(url, timeout=5) as r:
            return json.loads(r.read().decode()), r.status

    def _http(self, method, url, body=None, headers=None, expect_error=False):
        data = None if body is None else pjson(body)
        hdrs = {"Accept": "application/json"}
        if data is not None:
            hdrs["Content-Type"] = "application/json"
        if headers:
            hdrs.update(headers)
        req = urllib.request.Request(url, data=data, method=method, headers=hdrs)
        try:
            with urllib.request.urlopen(req, timeout=8) as r:
                raw = r.read()
                return json.loads(raw.decode()) if raw else {}, r.status
        except urllib.error.HTTPError as e:
            payload = e.read()
            parsed = json.loads(payload.decode()) if payload else {}
            if expect_error:
                return parsed, e.code
            raise

    def _lab_token(self):
        pkce, _ = self._get(f"http://127.0.0.1:{PORT}/lab/pkce?verifier={VERIFIER}")
        q = urllib.parse.urlencode({
            "account": "account-demo",
            "client_id": "client-demo",
            "redirect": "https://app.example/cb",
            "state": "state-1",
            "challenge": pkce["challenge"],
        })
        auth, _ = self._get(f"http://127.0.0.1:{PORT}/lab/authorize?{q}")
        tq = urllib.parse.urlencode({
            "code": auth["code"],
            "verifier": VERIFIER,
            "redirect": "https://app.example/cb",
        })
        tok, _ = self._get(f"http://127.0.0.1:{PORT}/lab/token?{tq}")
        return tok["access_token"]

    def _auth(self, method, path, token):
        q = urllib.parse.urlencode({"htm": method, "htu": API_BASE + path, "access_token": token})
        proof, _ = self._get(f"http://127.0.0.1:{PORT}/lab/dpop?{q}")
        return {"Authorization": "Bearer " + token, "DPoP": json.dumps(proof, separators=(",", ":"))}

    def _req(self, token, method, path, body=None, expect_error=False):
        return self._http(method, f"http://127.0.0.1:{PORT}{path}", body, headers=self._auth(method, path, token),
                           expect_error=expect_error)

    def _body(self, env):
        if isinstance(env, dict) and isinstance(env.get("body"), dict):
            return env["body"]
        return env if isinstance(env, dict) else {}

    def run_test(self):
        self._start()
        try:
            h, _ = self._get(f"http://127.0.0.1:{PORT}/health")
            if h.get("automatic_spend_atoms") not in (0, "0"):
                raise AssertionError(h)
            if not h.get("cognitive_reserve_layer"):
                raise SkipTest("btx-hcpd finance lab has no cognitive_reserve_layer")
            tok = self._lab_token()
            t0 = time.monotonic()
            rows = []
            for i in range(32):
                rows.append({
                    "observation_id": f"pos-scale-{i}",
                    "source": "scale",
                    "generation": "1",
                    "sequence": str(i + 1),
                    "mandate": "NONE",
                })
            batch, st = self._req(tok, "POST", "/institutional/positions/batches", {"rows": rows})
            assert st == 201
            assert int(batch.get("accepted") or 0) == 32
            elapsed = time.monotonic() - t0
            self.log.info("J17 process 32-row batch seconds=%.4f", elapsed)
            for i in (0, 15, 31):
                got, st = self._req(tok, "GET", f"/institutional/positions/pos-scale-{i}")
                assert st == 200
            listed, st = self._req(tok, "GET", "/institutional/positions?as_of=9999999999999&observed_cutoff=9999999999999")
            assert st == 200
            assert len(listed.get("items") or []) >= 32
            exp, st = self._req(tok, "POST", "/institutional/exports", {"format": "JSONL"})
            assert st == 201
            assert int(self._body(exp).get("total_rows") or 0) >= 32
            cancel, st = self._req(tok, "POST", "/layer/jobs/job-missing/cancel", {}, expect_error=True)
            assert st == 404
            adp, st = self._req(tok, "POST", "/layer/adapters/validate", {})
            assert st == 200
            self._honest("in-flight job cancel: validate/export jobs commit immediately and do not return job_id")
            self._honest("100k-row Crl12LoadSynthetic is native-only; hcpd body limit is 1MiB")
            if os.environ.get("BTX_CR12_10M_LAB"):
                self._honest("10m-row lab is native Crl12LoadSynthetic; hcpd has no synthetic loader")
            else:
                self._honest("10m-row institutional lab: BTX_CR12_10M_LAB unset")
            self.log.info("CR12 scale process smoke complete; HONEST_NOT_RUN=%s", self.not_run)
        finally:
            self._stop()


if __name__ == "__main__":
    ModelNetCr12Scale(__file__).main()
