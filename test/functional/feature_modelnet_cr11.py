#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Cognitive Reserve v1.1 process E2E: walletless vs funding lab gateways.

Isolated regtest only. Never production btxd. automatic_spend_atoms stays 0.
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


def pjson(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


class ModelNetCr11Test(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-nomodelnet", "-modelnet=0", *MATMUL_OFF_ARGS]]
        self.procs = []

    def setup_nodes(self):
        self.add_nodes(self.num_nodes, extra_args=self.extra_args)
        self.start_nodes()

    def skip_test_if_missing_module(self):
        self.skip_if_platform_not_posix()
        builddir = self.config["environment"].get("BUILDDIR")
        self.hcpd = Path(builddir) / "bin" / "btx-hcpd"
        if not self.hcpd.is_file():
            raise SkipTest("btx-hcpd not found")

    def _start(self, name, port, finance=False):
        d = Path(get_datadir_path(self.options.tmpdir, 0)) / name
        d.mkdir(parents=True, exist_ok=True)
        argv = [str(self.hcpd), f"-bind=127.0.0.1:{port}", f"-datadir={d}", f"-instance={name}"]
        argv.append("-finance=1" if finance else "-walletless")
        log = open(d / "hcpd.log", "w", encoding="utf-8")
        p = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT)
        for _ in range(50):
            if p.poll() is not None:
                break
            try:
                s = socket.create_connection(("127.0.0.1", port), 0.2)
                s.close()
                self.procs.append((p, log))
                return
            except OSError:
                time.sleep(0.1)
        p.terminate()
        log.close()
        raise RuntimeError(name)

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
        data = None if body is None else (body if isinstance(body, (bytes, bytearray)) else pjson(body))
        hdrs = {"Accept": "application/json"}
        if data is not None:
            hdrs["Content-Type"] = "application/json"
        if headers:
            hdrs.update(headers)
        req = urllib.request.Request(url, data=data, method=method, headers=hdrs)
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                raw = r.read()
                parsed = json.loads(raw.decode()) if raw else {}
                return parsed, r.status
        except urllib.error.HTTPError as e:
            payload = e.read()
            parsed = json.loads(payload.decode()) if payload else {}
            if expect_error:
                return parsed, e.code
            raise

    def _lab_token(self, port):
        pkce, _ = self._get(f"http://127.0.0.1:{port}/lab/pkce?verifier={VERIFIER}")
        q = urllib.parse.urlencode({
            "account": "account-demo",
            "client_id": "client-demo",
            "redirect": "https://app.example/cb",
            "state": "state-1",
            "challenge": pkce["challenge"],
        })
        auth, _ = self._get(f"http://127.0.0.1:{port}/lab/authorize?{q}")
        tq = urllib.parse.urlencode({
            "code": auth["code"],
            "verifier": VERIFIER,
            "redirect": "https://app.example/cb",
        })
        tok, _ = self._get(f"http://127.0.0.1:{port}/lab/token?{tq}")
        return tok["access_token"]

    def _auth(self, port, method, path, token):
        q = urllib.parse.urlencode({
            "htm": method,
            "htu": API_BASE + path,
            "access_token": token,
        })
        proof, _ = self._get(f"http://127.0.0.1:{port}/lab/dpop?{q}")
        return {
            "Authorization": "Bearer " + token,
            "DPoP": json.dumps(proof, separators=(",", ":")),
        }

    def run_test(self):
        self._start("A", 18790, False)
        self._start("B", 18791, True)
        try:
            ha, _ = self._get("http://127.0.0.1:18790/health")
            assert ha["walletless"] is True
            assert ha.get("cognitive_reserve") is False
            assert ha["automatic_spend_atoms"] == 0
            tok_a = self._lab_token(18790)
            ext, st = self._http("GET", "http://127.0.0.1:18790/extensions/cognitive-reserve",
                                  headers=self._auth(18790, "GET", "/extensions/cognitive-reserve", tok_a),
                                  expect_error=True)
            assert st == 403
            assert (ext.get("error") or {}).get("code") == "PROFILE_UNSUPPORTED"

            hb, _ = self._get("http://127.0.0.1:18791/health")
            assert hb["finance"] is True
            assert hb.get("cognitive_reserve") is True
            tok = self._lab_token(18791)
            ext, st = self._http("GET", "http://127.0.0.1:18791/extensions/cognitive-reserve",
                                 headers=self._auth(18791, "GET", "/extensions/cognitive-reserve", tok))
            assert st == 200
            assert ext["object_type"] == "ReserveExtensionProfileV1_1"
            portf, st = self._http("POST", "http://127.0.0.1:18791/reserve/portfolios",
                                   {"label": "working", "reporting_currency": "USD"},
                                   headers=self._auth(18791, "POST", "/reserve/portfolios", tok))
            assert st == 201
            pid = portf["body"]["portfolio_id"]
            snap, st = self._http("GET", f"http://127.0.0.1:18791/reserve/portfolios/{pid}/snapshot",
                                  headers=self._auth(18791, "GET", f"/reserve/portfolios/{pid}/snapshot", tok))
            assert st == 200
            assert snap["body"]["allocation_capacity_atoms"] == "250"
            cycle = {
                "client_operation_id": "cycle-1",
                "legs": [
                    {"leg_id": "A", "depends_on": ["B"]},
                    {"leg_id": "B", "depends_on": ["A"]},
                ],
            }
            bad, st = self._http("POST", "http://127.0.0.1:18791/capital/allocations", cycle,
                                  headers=self._auth(18791, "POST", "/capital/allocations", tok),
                                  expect_error=True)
            assert st == 400
            assert (bad.get("error") or {}).get("code") == "GRAPH_CYCLE"
            rpc, st = self._http("POST", "http://127.0.0.1:18791/rpc", {"method": "getbalance"}, expect_error=True)
            assert st == 404

            # Unique GET-by-id for previously unhit CR11 ops
            link, st = self._http(
                "POST",
                "http://127.0.0.1:18791/reserve/entities/links",
                {"parent_entity_id": "account-demo", "child_entity_id": "le-child"},
                headers=self._auth(18791, "POST", "/reserve/entities/links", tok),
            )
            assert st == 201
            lid = link["body"]["link_id"]
            got, st = self._http(
                "GET",
                f"http://127.0.0.1:18791/reserve/entities/links/{lid}",
                headers=self._auth(18791, "GET", f"/reserve/entities/links/{lid}", tok),
            )
            assert st == 200
            assert got["object_type"] == "EntityLinkV1_1"
            got, st = self._http(
                "GET",
                f"http://127.0.0.1:18791/reserve/portfolios/{pid}",
                headers=self._auth(18791, "GET", f"/reserve/portfolios/{pid}", tok),
            )
            assert st == 200
            pol, st = self._http(
                "POST",
                "http://127.0.0.1:18791/reserve/policies",
                {},
                headers=self._auth(18791, "POST", "/reserve/policies", tok),
            )
            assert st == 201
            pol_id = pol["body"]["policy_id"]
            got, st = self._http(
                "GET",
                f"http://127.0.0.1:18791/reserve/policies/{pol_id}",
                headers=self._auth(18791, "GET", f"/reserve/policies/{pol_id}", tok),
            )
            assert st == 200
            wl, st = self._http(
                "POST",
                "http://127.0.0.1:18791/capital/workloads",
                {},
                headers=self._auth(18791, "POST", "/capital/workloads", tok),
            )
            assert st == 201
            wid = wl["body"]["workload_id"]
            got, st = self._http(
                "GET",
                f"http://127.0.0.1:18791/capital/workloads/{wid}",
                headers=self._auth(18791, "GET", f"/capital/workloads/{wid}", tok),
            )
            assert st == 200
            tco, st = self._http(
                "POST",
                "http://127.0.0.1:18791/capital/comparisons",
                {"annual_tasks": "20000000", "service_per_task": "0.01", "years": 3, "upfront": "50000", "annual_local": "65000"},
                headers=self._auth(18791, "POST", "/capital/comparisons", tok),
            )
            assert st == 201
            cid = tco["body"]["comparison_id"]
            got, st = self._http(
                "GET",
                f"http://127.0.0.1:18791/capital/comparisons/{cid}",
                headers=self._auth(18791, "GET", f"/capital/comparisons/{cid}", tok),
            )
            assert st == 200
            plan, st = self._http(
                "POST",
                "http://127.0.0.1:18791/capital/plans",
                {},
                headers=self._auth(18791, "POST", "/capital/plans", tok),
            )
            assert st == 201
            plan_id = plan["body"]["plan_id"]
            got, st = self._http(
                "GET",
                f"http://127.0.0.1:18791/capital/plans/{plan_id}",
                headers=self._auth(18791, "GET", f"/capital/plans/{plan_id}", tok),
            )
            assert st == 200
            alloc, st = self._http(
                "POST",
                "http://127.0.0.1:18791/capital/allocations",
                {"client_operation_id": "getid-proc", "maximum_exposure": "10"},
                headers=self._auth(18791, "POST", "/capital/allocations", tok),
            )
            assert st == 201
            aid = alloc["body"]["allocation_id"]
            got, st = self._http(
                "GET",
                f"http://127.0.0.1:18791/capital/allocations/{aid}",
                headers=self._auth(18791, "GET", f"/capital/allocations/{aid}", tok),
            )
            assert st == 200
            xact, st = self._http(
                "POST",
                f"http://127.0.0.1:18791/capital/allocations/{aid}/execute",
                {},
                headers=self._auth(18791, "POST", f"/capital/allocations/{aid}/execute", tok),
            )
            assert st == 201
            xid = xact["body"]["execution_id"]
            got, st = self._http(
                "GET",
                f"http://127.0.0.1:18791/capital/executions/{xid}",
                headers=self._auth(18791, "GET", f"/capital/executions/{xid}", tok),
            )
            assert st == 200
            rule, st = self._http(
                "POST",
                "http://127.0.0.1:18791/capital/approval-rules",
                {},
                headers=self._auth(18791, "POST", "/capital/approval-rules", tok),
            )
            assert st == 201
            rid = rule["body"]["rule_id"]
            got, st = self._http(
                "GET",
                f"http://127.0.0.1:18791/capital/approval-rules/{rid}",
                headers=self._auth(18791, "GET", f"/capital/approval-rules/{rid}", tok),
            )
            assert st == 200
            apr, st = self._http(
                "POST",
                "http://127.0.0.1:18791/capital/approvals",
                {"rule_ref": rid},
                headers=self._auth(18791, "POST", "/capital/approvals", tok),
            )
            assert st == 201
            req_id = apr["body"]["request_id"]
            got, st = self._http(
                "GET",
                f"http://127.0.0.1:18791/capital/approvals/{req_id}",
                headers=self._auth(18791, "GET", f"/capital/approvals/{req_id}", tok),
            )
            assert st == 200
            got, st = self._http(
                "GET",
                f"http://127.0.0.1:18791/capital/approvals/{req_id}/decisions",
                headers=self._auth(18791, "GET", f"/capital/approvals/{req_id}/decisions", tok),
            )
            assert st == 200
            exp, st = self._http(
                "POST",
                "http://127.0.0.1:18791/capital/exports",
                {},
                headers=self._auth(18791, "POST", "/capital/exports", tok),
            )
            assert st == 201
            eid = exp["export_id"]
            got, st = self._http(
                "GET",
                f"http://127.0.0.1:18791/capital/exports/{eid}",
                headers=self._auth(18791, "GET", f"/capital/exports/{eid}", tok),
            )
            assert st == 200
            missing, st = self._http(
                "GET",
                "http://127.0.0.1:18791/capital/exports/missing",
                headers=self._auth(18791, "GET", "/capital/exports/missing", tok),
                expect_error=True,
            )
            assert st == 404
            hb2, _ = self._get("http://127.0.0.1:18791/health")
            assert hb2["automatic_spend_atoms"] == 0
        finally:
            self._stop()


if __name__ == "__main__":
    ModelNetCr11Test(__file__).main()
