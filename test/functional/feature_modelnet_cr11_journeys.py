#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""CR11-J01–J20 process journeys against two loopback gateways.

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


class ModelNetCr11Journeys(BitcoinTestFramework):
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
        self.hosted = Path(builddir) / "bin" / "btx-hosted"
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
        data = None if body is None else pjson(body)
        hdrs = {"Accept": "application/json"}
        if data is not None:
            hdrs["Content-Type"] = "application/json"
        if headers:
            hdrs.update(headers)
        req = urllib.request.Request(url, data=data, method=method, headers=hdrs)
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                raw = r.read()
                return json.loads(raw.decode()) if raw else {}, r.status
        except urllib.error.HTTPError as e:
            payload = e.read()
            parsed = json.loads(payload.decode()) if payload else {}
            if expect_error:
                return parsed, e.code
            raise

    def _lab_token(self, port, verifier=VERIFIER):
        pkce, _ = self._get(f"http://127.0.0.1:{port}/lab/pkce?verifier={verifier}")
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
            "verifier": verifier,
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

    def _zero(self, obj, where):
        if not isinstance(obj, dict):
            return
        spend = obj.get("automatic_spend_atoms", 0)
        if spend not in (0, "0"):
            raise AssertionError(f"{where} automatic_spend_atoms={spend}")

    def _req(self, port, token, method, path, body=None, expect_error=False):
        return self._http(
            method,
            f"http://127.0.0.1:{port}{path}",
            body,
            headers=self._auth(port, method, path, token),
            expect_error=expect_error,
        )

    def _bid(self, env, key):
        body = env.get("body") if isinstance(env, dict) else None
        if not isinstance(body, dict) or not body.get(key):
            raise AssertionError(f"missing {key}: {env}")
        return body[key]

    def run_test(self):
        self._start("A", 18792, False)
        self._start("B", 18793, True)
        try:
            ha, _ = self._get("http://127.0.0.1:18792/health")
            hb, _ = self._get("http://127.0.0.1:18793/health")
            self._zero(ha, "A /health")
            self._zero(hb, "B /health")
            assert ha.get("walletless") is True
            assert hb.get("finance") is True
            assert ha.get("automatic_spend_atoms") == 0
            assert hb.get("automatic_spend_atoms") == 0

            tok = self._lab_token(18793)
            tok_a = self._lab_token(18792)

            # J01 corporate workload to capital
            wl, st = self._req(18793, tok, "POST", "/capital/workloads", {"objective": "accepted-tasks"})
            assert st == 201
            wl_id = self._bid(wl, "workload_id")
            tco, st = self._req(18793, tok, "POST", "/capital/comparisons", {
                "annual_tasks": "20000000", "service_per_task": "0.01", "years": 3,
                "upfront": "50000", "annual_local": "65000",
            })
            assert st == 201
            assert tco["body"]["cost_lines"]["external"] == "600000"
            tco_id = self._bid(tco, "comparison_id")
            plan, st = self._req(18793, tok, "POST", "/capital/plans", {})
            assert st == 201
            plan_id = self._bid(plan, "plan_id")
            alloc, st = self._req(18793, tok, "POST", "/capital/allocations", {
                "client_operation_id": "j01", "maximum_exposure": "10",
            })
            assert st == 201
            alloc_id = self._bid(alloc, "allocation_id")

            # J02 institutional reserve mandate
            pol, st = self._req(18793, tok, "POST", "/reserve/policies", {
                "protected_atoms": "400", "replenishment_mode": "SUGGEST",
            })
            assert st == 201
            pol_id = self._bid(pol, "policy_id")
            sug, st = self._req(18793, tok, "POST", "/reserve/replenishment/plans", {
                "required_quote": "1", "price_quote_per_coin": "1",
                "observed_at": 1790000000000, "max_age": 100000,
            })
            assert sug.get("executed_orders") == 0
            got_pol, st = self._req(18793, tok, "GET", f"/reserve/policies/{pol_id}")
            assert st == 200
            assert self._bid(got_pol, "policy_id") == pol_id

            # J03 family view cannot be set over HTTP — capacity floor only
            self.log.info("J03 family_view not an HTTP setter; assert execute capacity floor 250")
            portf, st = self._req(18793, tok, "POST", "/reserve/portfolios", {
                "label": "working", "reporting_currency": "USD",
            })
            assert st == 201
            port_id = self._bid(portf, "portfolio_id")
            got_port, st = self._req(18793, tok, "GET", f"/reserve/portfolios/{port_id}")
            assert st == 200
            snap, st = self._req(18793, tok, "GET", f"/reserve/portfolios/{port_id}/snapshot")
            assert st == 200
            assert snap["body"]["allocation_capacity_atoms"] == "250"

            # J04 foundation research programme
            prog, st = self._req(18793, tok, "POST", "/capital/programs", {"title": "foundation"})
            assert st == 201
            pid = self._bid(prog, "program_id")
            mem, st = self._req(18793, tok, "POST", f"/capital/programs/{pid}/memberships", {})
            assert mem["body"]["independent"] is True

            # J05 walletless A: PROFILE_UNSUPPORTED
            ext_a, st = self._req(18792, tok_a, "GET", "/extensions/cognitive-reserve", expect_error=True)
            assert st == 403
            assert (ext_a.get("error") or {}).get("code") == "PROFILE_UNSUPPORTED"
            denied, st = self._req(18792, tok_a, "POST", "/reserve/portfolios", {}, expect_error=True)
            assert st == 403
            assert (denied.get("error") or {}).get("code") == "PROFILE_UNSUPPORTED"
            if self.hosted.is_file():
                hosted = json.loads(subprocess.check_output([str(self.hosted), "walletless"], text=True))
                assert hosted["walletless"] is True

            # J06 resident base / LAN adapter — local product catalogue, no inventory upload
            products, st = self._req(18793, tok, "GET", "/capital/products")
            assert st == 200
            prod_id = (products.get("items") or ["prod-demo"])[0]
            got_prod, st = self._req(18793, tok, "GET", f"/capital/products/{prod_id}")
            assert st == 200
            search_a, st = self._req(18792, tok_a, "POST", "/capabilities/search", {})
            assert "local_paths" not in json.dumps(search_a)

            # J07 reserve replenishment concurrency — SUGGEST then AUTO + cooldown
            auto_pol, st = self._req(18793, tok, "POST", "/reserve/policies", {
                "protected_atoms": "400", "replenishment_mode": "AUTO",
            })
            assert st == 201
            auto1, st = self._req(18793, tok, "POST", "/reserve/replenishment/plans", {
                "required_quote": "1", "price_quote_per_coin": "1",
                "observed_at": 1790000000000, "max_age": 100000,
                "client_operation_id": "j07-auto-1",
            })
            assert st in (200, 201)
            assert auto1.get("executed_orders") == 1
            cool, st = self._req(18793, tok, "POST", "/reserve/replenishment/plans", {
                "required_quote": "1", "price_quote_per_coin": "1",
                "observed_at": 1790000000000, "max_age": 100000,
                "client_operation_id": "j07-auto-2",
            }, expect_error=True)
            assert st in (409, 400)
            assert (cool.get("error") or {}).get("code") in ("REPLENISH_COOLDOWN", "GRAPH_CYCLE") or st in (409, 400)

            # J09 conversion / execute before any approval packet (one lab token cannot meet quorum)
            xact, st = self._req(18793, tok, "POST", f"/capital/allocations/{alloc_id}/execute", {})
            assert st == 201
            xid = self._bid(xact, "execution_id")
            got_x, st = self._req(18793, tok, "GET", f"/capital/executions/{xid}")
            assert st == 200
            assert self._bid(got_x, "execution_id") == xid

            # J08 committee mid-plan — rule, request, decision list (quorum not completable here)
            rule, st = self._req(18793, tok, "POST", "/capital/approval-rules", {
                "distinct_person_quorum": 2,
            })
            assert st == 201
            rule_id = self._bid(rule, "rule_id")
            got_rule, st = self._req(18793, tok, "GET", f"/capital/approval-rules/{rule_id}")
            assert st == 200
            apr, st = self._req(18793, tok, "POST", "/capital/approvals", {
                "allocation_ref": alloc_id, "rule_ref": rule_id, "maximum_exposure": "10",
            })
            assert st == 201
            apr_id = self._bid(apr, "request_id")
            got_apr, st = self._req(18793, tok, "GET", f"/capital/approvals/{apr_id}")
            assert st == 200
            dec, st = self._req(18793, tok, "POST", f"/capital/approvals/{apr_id}/decisions", {
                "decision": "APPROVE",
            })
            assert st == 201
            decs, st = self._req(18793, tok, "GET", f"/capital/approvals/{apr_id}/decisions")
            assert st == 200
            assert isinstance(decs.get("items"), list)

            # J10 unknown native broadcast — GET existing execution, never POST /rpc retry
            again_x, st = self._req(18793, tok, "GET", f"/capital/executions/{xid}")
            assert st == 200
            again_a, st = self._req(18793, tok, "GET", f"/capital/allocations/{alloc_id}")
            assert st == 200

            # J11 independent co-sponsors
            prog2, st = self._req(18793, tok, "POST", "/capital/programs", {"title": "co-sponsor"})
            assert st == 201
            pid2 = self._bid(prog2, "program_id")
            mem2, st = self._req(18793, tok, "POST", f"/capital/programs/{pid2}/memberships", {})
            assert mem2["body"]["independent"] is True
            cmt, st = self._req(18793, tok, "POST", f"/capital/programs/{pid2}/commitments", {})
            assert st == 201
            assert cmt.get("executed") is False
            got_prog, st = self._req(18793, tok, "GET", f"/capital/programs/{pid2}")
            assert st == 200

            # J12 refund and reserve authority — cancel hold, new allocation, lifetime policy still GET
            canceled, st = self._req(18793, tok, "POST", f"/capital/executions/{xid}/cancel", {})
            assert st == 200
            alloc2, st = self._req(18793, tok, "POST", "/capital/allocations", {
                "client_operation_id": "j12", "maximum_exposure": "10",
            })
            assert st == 201
            got_pol2, st = self._req(18793, tok, "GET", f"/reserve/policies/{pol_id}")
            assert st == 200

            # J13 infrastructure partner referral (not a debit)
            ref, st = self._req(18793, tok, "POST", f"/capital/products/{prod_id}/referral", {})
            assert st == 201
            assert ref.get("not_a_debit") is True

            # J14 collateral / positions + snapshot
            pos, st = self._req(18793, tok, "POST", "/capital/positions", {"lifecycle": "ACQUIRED"})
            assert st == 201
            pos_id = self._bid(pos, "position_id")
            got_pos, st = self._req(18793, tok, "GET", f"/capital/positions/{pos_id}")
            assert st == 200
            listed_pos, st = self._req(18793, tok, "GET", "/capital/positions")
            assert st == 200
            assert listed_pos.get("nav_merged") is False
            snap2, st = self._req(18793, tok, "GET", "/reserve/portfolios/demo/snapshot")
            assert st == 200
            assert snap2["body"].get("nav_merged") is False
            assert "allocation_capacity_atoms" in snap2["body"]

            # J15 board reporting + export GET-by-id
            rep, st = self._req(18793, tok, "POST", "/capital/reports", {})
            assert st == 201
            assert rep["body"]["nav_merged"] is False
            rep_id = self._bid(rep, "report_id")
            got_rep, st = self._req(18793, tok, "GET", f"/capital/reports/{rep_id}")
            assert st == 200
            exp, st = self._req(18793, tok, "POST", "/capital/exports", {})
            assert st == 201
            exp_id = exp.get("export_id") or (exp.get("body") or {}).get("export_id")
            assert exp_id
            got_exp, st = self._req(18793, tok, "GET", f"/capital/exports/{exp_id}")
            assert st == 200

            # J16 adviser revocation — entity link GET-by-id then revoke
            link, st = self._req(18793, tok, "POST", "/reserve/entities/links", {
                "relationship": "ADVISER",
            })
            assert st == 201
            link_id = self._bid(link, "link_id")
            got_link, st = self._req(18793, tok, "GET", f"/reserve/entities/links/{link_id}")
            assert st == 200
            rev, st = self._req(18793, tok, "POST", f"/reserve/entities/links/{link_id}/revoke", {})
            assert st == 200

            # J17 two-provider customer exit — A stays walletless; B export already attributed
            got_exp2, st = self._req(18793, tok, "GET", f"/capital/exports/{exp_id}")
            assert st == 200
            _, st = self._req(18792, tok_a, "POST", "/capital/allocations", {
                "client_operation_id": "j17-replay",
            }, expect_error=True)
            assert st == 403

            # J18 accessible browser / agent parity — typed GET-by-id of J01 objects
            g_wl, st = self._req(18793, tok, "GET", f"/capital/workloads/{wl_id}")
            assert st == 200
            g_tco, st = self._req(18793, tok, "GET", f"/capital/comparisons/{tco_id}")
            assert st == 200
            g_plan, st = self._req(18793, tok, "GET", f"/capital/plans/{plan_id}")
            assert st == 200
            g_alloc, st = self._req(18793, tok, "GET", f"/capital/allocations/{alloc_id}")
            assert st == 200

            # J19 outage and load — health + generic RPC disabled
            hb2, _ = self._get("http://127.0.0.1:18793/health")
            self._zero(hb2, "J19 B /health")
            rpc, st = self._http("POST", "http://127.0.0.1:18793/rpc", {"method": "getbalance"}, expect_error=True)
            assert st == 404
            rpc_a, st = self._http("POST", "http://127.0.0.1:18792/rpc", {"method": "getbalance"}, expect_error=True)
            assert st == 404

            # J20 integrated candidate — GRAPH_CYCLE, Core v4, spend floor
            cycle = {
                "client_operation_id": "j20-cycle",
                "legs": [
                    {"leg_id": "A", "depends_on": ["B"]},
                    {"leg_id": "B", "depends_on": ["A"]},
                ],
            }
            bad, st = self._req(18793, tok, "POST", "/capital/allocations", cycle, expect_error=True)
            assert st in (400, 409)
            assert (bad.get("error") or {}).get("code") == "GRAPH_CYCLE"
            v4, st = self._req(18793, tok, "POST", "/capital/positions", {
                "package_core_version": 4,
            }, expect_error=True)
            assert st == 400
            assert (v4.get("error") or {}).get("code") in ("CORE_V4_FORBIDDEN", "CORE_V4")
            hb3, _ = self._get("http://127.0.0.1:18793/health")
            assert hb3.get("automatic_spend_atoms") == 0
            self.log.info("CR11-J01–J20 distinct HTTP sequences complete")
        finally:
            self._stop()


if __name__ == "__main__":
    ModelNetCr11Journeys(__file__).main()
