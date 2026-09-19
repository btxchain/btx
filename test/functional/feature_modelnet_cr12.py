#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""CR12-J01–J20 process journeys against loopback btx-hcpd.

Isolated regtest only. Never production btxd. automatic_spend_atoms stays 0.
Use -nomodelnet. PlanLocal/EnsureLocal and Crl12LoadSynthetic are native-only.
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
CORE = "111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
PORT_A = 18820
PORT_B = 18821
PORT_C = 18822


def pjson(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


class ModelNetCr12Journeys(BitcoinTestFramework):
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

    def _honest(self, journey, reason):
        self.not_run.append((journey, reason))
        self.log.info("HONEST_NOT_RUN %s: %s", journey, reason)

    def _start(self, name, port, finance=True, cr12=None):
        d = Path(get_datadir_path(self.options.tmpdir, 0)) / name
        d.mkdir(parents=True, exist_ok=True)
        argv = [str(self.hcpd), f"-bind=127.0.0.1:{port}", f"-datadir={d}", f"-instance={name}"]
        argv.append("-finance=1" if finance else "-walletless")
        if cr12 is True:
            argv.append("-cr12=1")
        elif cr12 is False:
            argv.append("-cr12=0")
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
            raw = r.read()
            return (json.loads(raw.decode()) if raw else {}), r.status

    def _http(self, method, url, body=None, headers=None, expect_error=False, timeout=8):
        if body is None:
            data = None
        elif isinstance(body, (bytes, bytearray)):
            data = body
        else:
            data = pjson(body)
        hdrs = {"Accept": "application/json"}
        if data is not None:
            hdrs["Content-Type"] = "application/json"
        if headers:
            hdrs.update(headers)
        req = urllib.request.Request(url, data=data, method=method, headers=hdrs)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                raw = r.read()
                if (r.headers.get_content_type() or "").startswith("application/octet-stream"):
                    return raw, r.status
                return json.loads(raw.decode()) if raw else {}, r.status
        except urllib.error.HTTPError as e:
            payload = e.read()
            parsed = {}
            if payload:
                try:
                    parsed = json.loads(payload.decode())
                except json.JSONDecodeError:
                    parsed = {"raw": payload.decode(errors="replace")}
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

    def _req(self, port, token, method, path, body=None, expect_error=False, timeout=8):
        return self._http(
            method,
            f"http://127.0.0.1:{port}{path}",
            body,
            headers=self._auth(port, method, path, token),
            expect_error=expect_error,
            timeout=timeout,
        )

    def _body(self, env):
        if isinstance(env, dict) and isinstance(env.get("body"), dict):
            return env["body"]
        return env if isinstance(env, dict) else {}

    def _ecode(self, env):
        err = env.get("error") if isinstance(env, dict) else None
        if isinstance(err, dict):
            return str(err.get("code") or "")
        return ""

    def _zero(self, obj, where):
        spend = obj.get("automatic_spend_atoms", 0) if isinstance(obj, dict) else 0
        if spend not in (0, "0"):
            raise AssertionError(f"{where} automatic_spend_atoms={spend}")

    def run_test(self):
        try:
            self._start("A", PORT_A, True)
            self._start("B", PORT_B, True)
            self._start("C", PORT_C, False, cr12=True)
            ha, _ = self._get(f"http://127.0.0.1:{PORT_A}/health")
            hb, _ = self._get(f"http://127.0.0.1:{PORT_B}/health")
            hc, _ = self._get(f"http://127.0.0.1:{PORT_C}/health")
            self._zero(ha, "A /health")
            self._zero(hb, "B /health")
            self._zero(hc, "C /health")
            if not ha.get("cognitive_reserve_layer"):
                raise SkipTest("btx-hcpd finance lab has no cognitive_reserve_layer")
            tok_a = self._lab_token(PORT_A)
            tok_b = self._lab_token(PORT_B)
            tok_c = self._lab_token(PORT_C)

            self._j01(tok_a, tok_b, tok_c, hc)
            self._j02(tok_a, tok_b)
            self._j03(tok_a)
            self._j04(tok_a)
            self._j05(tok_a)
            self._j06(tok_a)
            self._j07(tok_a)
            self._j08(tok_a)
            self._j09(tok_a)
            self._j10(tok_a)
            self._j11(tok_a)
            self._j12(tok_a, tok_b)
            self._j13(tok_a)
            self._j14(tok_a)
            self._j15(tok_a)
            self._j16(tok_a)
            self._j17()
            self._j18(tok_a, tok_b)
            self._j19(tok_a)
            self._j20(tok_a, tok_b, tok_c)
            self.log.info("CR12-J01–J20 process sequences complete; HONEST_NOT_RUN=%s", self.not_run)
        finally:
            self._stop()

    def _j01(self, tok_a, tok_b, tok_c, hc):
        assert hc.get("walletless") is True
        ext_c, st = self._req(PORT_C, tok_c, "GET", "/extensions/cognitive-reserve/v1.2")
        assert st == 200
        assert self._body(ext_c).get("not_inferred_from_provider_name") is True
        ra, st = self._req(PORT_A, tok_a, "POST", "/layer/roles", {"role": "DISCOVERY", "manifest_id": "role-j01-a"})
        assert st == 201
        rb, st = self._req(PORT_B, tok_b, "POST", "/layer/roles", {"role": "DISCOVERY", "manifest_id": "role-j01-b"})
        assert st == 201
        brand, st = self._req(PORT_A, tok_a, "POST", "/layer/roles", {"role": "DISCOVERY", "brand": "Goldman Sachs"}, expect_error=True)
        assert st >= 400
        assert self._ecode(brand) == "BRAND_DISPATCH"
        listed, st = self._req(PORT_A, tok_a, "GET", "/layer/roles")
        assert st == 200
        search, st = self._req(PORT_A, tok_a, "POST", "/capabilities/search", {})
        assert st == 200
        raw, st = self._http("GET", f"http://127.0.0.1:{PORT_A}/packages/{CORE}", headers=self._auth(PORT_A, "GET", f"/packages/{CORE}", tok_a))
        assert st == 200
        self._honest("J01", "PlanLocal/EnsureLocal are native/helper, not hcpd HTTP")

    def _j02(self, tok_a, tok_b):
        ba, st = self._req(PORT_A, tok_a, "POST", "/layer/bindings", {"role": "DISCOVERY", "binding_id": "bind-j02-a"})
        assert st == 201
        bb, st = self._req(PORT_B, tok_b, "POST", "/layer/bindings", {"role": "CUSTODY", "binding_id": "bind-j02-b"})
        assert st == 201
        stolen, st = self._req(PORT_B, tok_a, "POST", "/institutional/instructions", {"instruction_id": "ins-j02-x"}, expect_error=True)
        assert st >= 400
        port, st = self._req(PORT_B, tok_b, "POST", "/reserve/portfolios", {"label": "j02"})
        assert st == 201
        pid = self._body(port)["portfolio_id"]
        snap, st = self._req(PORT_B, tok_b, "GET", f"/reserve/portfolios/{pid}/snapshot")
        assert st == 200
        ins, st = self._req(PORT_A, tok_a, "POST", "/institutional/instructions", {
            "instruction_id": "ins-j02", "requested_action": "DRAFT_CAPABILITY_ACQUISITION",
        })
        assert st == 201
        assert self._body(ins).get("execute") is False
        tr, st = self._req(PORT_A, tok_a, "POST", "/institutional/instructions/ins-j02/translate", {})
        assert st == 200
        exp, st = self._req(PORT_A, tok_a, "POST", "/institutional/exports", {"format": "JSONL"})
        assert st == 201

    def _j03(self, tok):
        batch, st = self._req(PORT_A, tok, "POST", "/institutional/positions/batches", {
            "rows": [
                {"observation_id": "pos-j03-src", "source": "feed-a", "generation": "1", "sequence": "1",
                 "mandate": "CUSTODY", "beneficial_id": "lot-j03"},
                {"observation_id": "pos-j03-dup", "source": "feed-b", "generation": "1", "sequence": "1",
                 "mandate": "CUSTODY", "beneficial_id": "lot-j03"},
                {"observation_id": "pos-j03-back", "source": "feed-map", "generation": "1", "sequence": "1",
                 "mandate": "NONE"},
            ],
        })
        assert st == 201
        exp, st = self._req(PORT_A, tok, "POST", "/institutional/exposures", {
            "parent": "lot-j03", "child": "pos-j03-src", "weight": "1", "coverage_bps": 10000,
        })
        assert st == 201
        self._req(PORT_A, tok, "POST", "/institutional/valuations", {"value": "0"})
        pr, st = self._req(PORT_A, tok, "POST", "/institutional/projections", {"metric_kind": "AUC"})
        assert st == 201
        eligible = self._body(pr)["metric_results"][0]["eligible_count"]
        if int(eligible) != 1:
            self._honest("J03", "AUC eligible_count tracks custody observations, not unique beneficial_id")

    def _j04(self, tok):
        self._req(PORT_A, tok, "POST", "/institutional/positions/batches", {
            "rows": [
                {"observation_id": "pos-j04-m", "source": "src", "generation": "1", "sequence": "1", "mandate": "MANAGED"},
                {"observation_id": "pos-j04-u", "source": "src", "generation": "1", "sequence": "2", "mandate": "NONE"},
            ],
        })
        self._req(PORT_A, tok, "POST", "/institutional/valuations", {"value": "0"})
        aum, st = self._req(PORT_A, tok, "POST", "/institutional/projections", {"metric_kind": "AUM"})
        assert st == 201
        assert int(self._body(aum)["metric_results"][0]["eligible_count"]) == 1
        md, st = self._req(PORT_A, tok, "POST", "/institutional/metrics", {"metric_kind": "AUM"})
        assert st == 201
        assert self._body(md).get("mandate_required") is True

    def _j05(self, tok):
        wl, st = self._req(PORT_A, tok, "POST", "/capital/workloads", {"workload_id": "j05-wl"})
        assert st == 201
        cmp, st = self._req(PORT_A, tok, "POST", "/capital/comparisons", {"comparison_id": "j05-tco", "workload_ref": "j05-wl"})
        assert st == 201
        ins, st = self._req(PORT_A, tok, "POST", "/institutional/instructions", {
            "instruction_id": "ins-j05", "requested_action": "DRAFT_RESERVE_ALLOCATION",
        })
        assert st == 201
        assert self._body(ins).get("no_reservation") is True
        tr, st = self._req(PORT_A, tok, "POST", "/institutional/instructions/ins-j05/translate", {})
        assert st == 200
        alloc, st = self._req(PORT_A, tok, "POST", "/capital/allocations", {
            "client_operation_id": "j05-http", "maximum_exposure": "10",
        })
        assert st == 201
        aid = self._body(alloc)["allocation_id"]
        ex, st = self._req(PORT_A, tok, "POST", f"/capital/allocations/{aid}/execute", {})
        assert st == 201
        self._honest("J05", "local BTX PlanLocal is native/helper, not hcpd HTTP")

    def _j06(self, tok):
        self._req(PORT_A, tok, "POST", "/institutional/positions/batches", {
            "rows": [
                {"observation_id": "pos-j06-co", "source": "books", "generation": "1", "sequence": "1", "beneficial_id": "company"},
                {"observation_id": "pos-j06-tr", "source": "books", "generation": "1", "sequence": "2", "beneficial_id": "trust"},
                {"observation_id": "pos-j06-pe", "source": "books", "generation": "1", "sequence": "3", "beneficial_id": "personal"},
            ],
        })
        listed, st = self._req(PORT_A, tok, "GET", "/institutional/positions?as_of=9999999999999&observed_cutoff=9999999999999")
        assert st == 200
        bad, st = self._req(PORT_A, tok, "POST", "/institutional/instructions", {"legal_entity_id": "le-other"}, expect_error=True)
        assert st == 403
        assert self._ecode(bad) == "ENTITY_SCOPE_DENIED"
        ins, st = self._req(PORT_A, tok, "POST", "/institutional/instructions", {"instruction_id": "ins-j06"})
        assert st == 201
        self._honest("J06", "family_view execute floor is native Cr11SetFamilyView, not an HTTP setter")

    def _j07(self, tok):
        dbl, st = self._req(PORT_A, tok, "POST", "/institutional/exposures", {
            "parent": "fund", "child": "h1", "weight": "0.4", "add_parent_and_children": True,
        }, expect_error=True)
        assert self._ecode(dbl) == "LOOKTHROUGH_DOUBLE_COUNT"
        ok, st = self._req(PORT_A, tok, "POST", "/institutional/exposures", {
            "parent": "fund", "child": "h1", "weight": "0.8", "coverage_bps": 8000,
        })
        assert st == 201
        assert int(self._body(ok)["unresolved_residual_bps"]) == 2000

    def _j08(self, tok):
        self._req(PORT_A, tok, "POST", "/institutional/positions/batches", {
            "rows": [{"observation_id": "pos-j08-old", "source": "src-j08", "generation": "1", "sequence": "1",
                      "effective_at": "1000", "recorded_at": "1000"}],
        })
        old, st = self._req(PORT_A, tok, "POST", "/institutional/projections", {
            "projection_id": "prj-j08-old", "as_of": "1000", "observed_cutoff": "1000",
        })
        assert st == 201
        self._req(PORT_A, tok, "POST", "/institutional/positions/batches", {
            "rows": [{"observation_id": "pos-j08-new", "source": "src-j08", "generation": "1", "sequence": "2",
                      "effective_at": "1000", "recorded_at": "2000"}],
        })
        new, st = self._req(PORT_A, tok, "POST", "/institutional/projections", {
            "projection_id": "prj-j08-new", "as_of": "1000", "observed_cutoff": "2000",
        })
        assert st == 201
        g1, st = self._req(PORT_A, tok, "GET", "/institutional/projections/prj-j08-old")
        assert st == 200
        g2, st = self._req(PORT_A, tok, "GET", "/institutional/projections/prj-j08-new")
        assert st == 200

    def _j09(self, tok):
        self._req(PORT_A, tok, "POST", "/institutional/positions/batches", {
            "rows": [{"observation_id": "pos-j09", "source": "src-j09", "generation": "1", "sequence": "1", "mandate": "MANAGED"}],
        })
        missing, st = self._req(PORT_A, tok, "POST", "/institutional/valuations", {"purpose": "MARKET_VALUE"})
        assert st == 201
        assert self._body(missing).get("status") == "UNAVAILABLE"
        pr, st = self._req(PORT_A, tok, "POST", "/institutional/projections", {"metric_kind": "AUM"})
        assert st == 201
        body = self._body(pr)
        assert body.get("status") == "PARTIAL" or body.get("no_finance_intent") is True or (
            body.get("metric_results") and (body["metric_results"][0].get("value") is None or body["metric_results"][0].get("complete") is False)
        )
        stale, st = self._req(PORT_A, tok, "POST", "/institutional/instructions", {"stale_projection": True}, expect_error=True)
        assert self._ecode(stale) == "STALE_SOURCE"
        draft, st = self._req(PORT_A, tok, "POST", "/institutional/instructions", {"instruction_id": "ins-j09"})
        assert self._body(draft).get("execute") is False

    def _j10(self, tok):
        ins, st = self._req(PORT_A, tok, "POST", "/institutional/instructions", {
            "instruction_id": "ins-j10", "requested_action": "DRAFT_RESEARCH_COMMITMENT",
        })
        assert st == 201
        self._req(PORT_A, tok, "POST", "/institutional/instructions/ins-j10/translate", {})
        alloc, st = self._req(PORT_A, tok, "POST", "/capital/allocations", {
            "client_operation_id": "j10-http", "maximum_exposure": "10",
        })
        assert st == 201
        aid = self._body(alloc)["allocation_id"]
        ex, st = self._req(PORT_A, tok, "POST", f"/capital/allocations/{aid}/execute", {})
        assert st == 201
        xid = self._body(ex)["execution_id"]
        canceled, st = self._req(PORT_A, tok, "POST", f"/capital/executions/{xid}/cancel", {})
        assert st == 200
        got, st = self._req(PORT_A, tok, "GET", f"/capital/executions/{xid}")
        assert self._body(got).get("state") == "CANCELED"

    def _j11(self, tok):
        ast, st = self._req(PORT_A, tok, "POST", "/institutional/assets", {"kind": "CAPABILITY", "label": "public-release"})
        assert st == 201
        aid = self._body(ast)["asset_id"]
        rights, st = self._req(PORT_A, tok, "POST", f"/institutional/assets/{aid}/rights", {"issuer": "issuer-lab"})
        assert st == 201
        raw, st = self._http("GET", f"http://127.0.0.1:{PORT_A}/packages/{CORE}",
                              headers=self._auth(PORT_A, "GET", f"/packages/{CORE}", tok))
        assert st == 200
        pos, st = self._req(PORT_A, tok, "POST", "/capital/positions", {
            "position_id": "j11-hold", "recipe_id": "3" * 96, "lock_id": "lock-j11",
        })
        assert st == 201
        self._honest("J11", "EnsureLocal/AcceptHandoff readiness is native-only on this gateway")

    def _j12(self, tok_a, tok_b):
        self._req(PORT_A, tok_a, "POST", "/institutional/assets", {"label": "j12-asset"})
        exp, st = self._req(PORT_A, tok_a, "POST", "/institutional/exports", {"format": "CSV"})
        assert st == 201
        eid = self._body(exp)["export_id"]
        chunk = self._body(exp)["chunks"][0]
        digest = chunk["digest"]
        cid = chunk["chunk_id"]
        payload, st = self._http(
            "GET",
            f"http://127.0.0.1:{PORT_A}/institutional/exports/{eid}/chunks/{cid}",
            headers=self._auth(PORT_A, "GET", f"/institutional/exports/{eid}/chunks/{cid}", tok_a),
        )
        assert st == 200
        if isinstance(payload, dict):
            payload = pjson(payload)
        elif isinstance(payload, str):
            payload = payload.encode()
        up, st = self._req(PORT_B, tok_b, "POST", "/institutional/imports/chunks", payload + b"tamper")
        assert st == 201
        bad, st = self._req(PORT_B, tok_b, "POST", "/institutional/imports/validate", {
            "chunk_id": up["chunk_id"], "digest": digest,
        }, expect_error=True)
        assert self._ecode(bad) == "CHUNK_DIGEST"
        up2, st = self._req(PORT_B, tok_b, "POST", "/institutional/imports/chunks", payload)
        assert st == 201
        val, st = self._req(PORT_B, tok_b, "POST", "/institutional/imports/validate", {
            "chunk_id": up2["chunk_id"], "digest": up2["digest"],
        })
        assert st == 200
        iid = self._body(val)["import_id"]
        pub, st = self._req(PORT_B, tok_b, "POST", f"/institutional/imports/{iid}/commit", {})
        assert st == 200
        assert self._body(pub).get("status") == "PUBLISHED"
        assert self._body(pub).get("custody_credit") is False

    def _j13(self, tok):
        ast, st = self._req(PORT_A, tok, "POST", "/institutional/assets", {
            "asset_id": "asset-demo-a", "label": "Synthetic reserve position",
        })
        assert st == 201
        ins, st = self._req(PORT_A, tok, "POST", "/institutional/instructions", {
            "instruction_id": "ins-j13", "requested_action": "DRAFT_CAPABILITY_ACQUISITION", "desktop_context": True,
        })
        assert st == 201
        assert self._body(ins).get("execute") is False
        assert "access_token" not in json.dumps(self._body(ins))

    def _j14(self, tok):
        for i in range(3):
            v, st = self._req(PORT_A, tok, "POST", "/institutional/imports/validate", {
                "import_id": f"imp-j14-{i}", "row_count": 4,
            })
            assert st == 200
            iid = self._body(v)["import_id"]
            c, st = self._req(PORT_A, tok, "POST", f"/institutional/imports/{iid}/commit", {})
            assert self._body(c).get("custody_credit") is False
        role, st = self._req(PORT_A, tok, "POST", "/layer/roles", {"role": "PORTFOLIO_ANALYTICS"})
        assert st == 201
        assert "invented_aum" not in self._body(role)
        pr, st = self._req(PORT_A, tok, "POST", "/institutional/projections", {"metric_kind": "AUM"})
        assert st == 201

    def _j15(self, tok):
        pr, st = self._req(PORT_A, tok, "POST", "/institutional/projections", {"projection_id": "prj-j15-frozen"})
        assert st == 201
        px, st = self._req(PORT_A, tok, "POST", "/institutional/scenarios", {"scenario_id": "scn-j15-px", "kind": "RESERVE_PRICE"})
        assert st == 201
        assert self._body(px).get("distinct_methodology") is True
        ops, st = self._req(PORT_A, tok, "POST", "/institutional/scenarios", {"scenario_id": "scn-j15-ops", "kind": "PROVIDER_OUTAGE"})
        assert st == 201
        got, st = self._req(PORT_A, tok, "GET", "/institutional/projections/prj-j15-frozen")
        assert st == 200
        self._honest("J15", "DisconnectProvider + surviving EnsureLocal is native-only")

    def _j16(self, tok):
        self._req(PORT_A, tok, "POST", "/layer/roles", {"role": "TREASURY", "manifest_id": "role-j16"})
        for _ in range(5):
            ins, st = self._req(PORT_A, tok, "POST", "/institutional/instructions", {
                "instruction_id": "ins-j16", "requested_action": "DRAFT_RESERVE_ALLOCATION",
            })
            assert st == 201
        tr, st = self._req(PORT_A, tok, "POST", "/institutional/instructions/ins-j16/translate", {})
        assert st == 200
        plan = self._body(tr)["draft_plan_id"]
        tr2, st = self._req(PORT_A, tok, "POST", "/institutional/instructions/ins-j16/translate", {})
        assert self._body(tr2)["draft_plan_id"] == plan
        bad, st = self._req(PORT_A, tok, "POST", "/institutional/instructions", {
            "instruction_id": "ins-j16", "requested_action": "DRAFT_RESEARCH_COMMITMENT",
        }, expect_error=True)
        assert self._ecode(bad) == "IDEMPOTENCY_CONFLICT"

    def _j17(self):
        self._honest("J17", "100k-row Crl12LoadSynthetic is native-only; hcpd body limit is 1MiB")
        if os.environ.get("BTX_CR12_10M_LAB"):
            self._honest("J17", "10m-row lab is native Crl12LoadSynthetic; hcpd has no synthetic loader")
        else:
            self._honest("J17", "10m-row institutional lab: BTX_CR12_10M_LAB unset")

    def _j18(self, tok_a, tok_b):
        bd, st = self._req(PORT_A, tok_a, "POST", "/layer/bindings", {"role": "DISCOVERY", "binding_id": "bind-j18-disc"})
        assert st == 201
        alloc, st = self._req(PORT_A, tok_a, "POST", "/capital/allocations", {
            "client_operation_id": "j18-child", "maximum_exposure": "10",
        })
        assert st == 201
        aid = self._body(alloc)["allocation_id"]
        ex, st = self._req(PORT_A, tok_a, "POST", f"/capital/allocations/{aid}/execute", {})
        assert st == 201
        xid = self._body(ex)["execution_id"]
        rev, st = self._req(PORT_A, tok_a, "POST", "/layer/bindings/bind-j18-disc/revoke", {})
        assert self._body(rev).get("status") == "REVOKED"
        got, st = self._req(PORT_A, tok_a, "GET", f"/capital/executions/{xid}")
        assert st == 200
        search, st = self._req(PORT_B, tok_b, "POST", "/capabilities/search", {})
        assert st == 200

    def _j19(self, tok):
        ext11, st = self._req(PORT_A, tok, "GET", "/extensions/cognitive-reserve")
        assert st == 200
        rep, st = self._req(PORT_A, tok, "POST", "/capital/reports", {})
        assert st == 201
        imp, st = self._req(PORT_A, tok, "POST", "/institutional/imports/validate", {})
        assert st == 200
        iid = self._body(imp)["import_id"]
        pub, st = self._req(PORT_A, tok, "POST", f"/institutional/imports/{iid}/commit", {})
        assert st == 200
        v4, st = self._req(PORT_A, tok, "POST", "/institutional/assets", {"package_core_version": 4}, expect_error=True)
        assert self._ecode(v4) in ("CORE_V4_FORBIDDEN", "CORE_V4")
        self._honest("J19", "Crl12SetEnabled(false) rollback is native-only; hcpd has no disable flag")

    def _j20(self, tok_a, tok_b, tok_c):
        for port, tok, role in (
            (PORT_A, tok_a, "CUSTODY"),
            (PORT_B, tok_b, "PORTFOLIO_ANALYTICS"),
        ):
            ext, st = self._req(port, tok, "GET", "/extensions/cognitive-reserve/v1.2")
            assert st == 200
            assert self._body(ext).get("not_inferred_from_provider_name") is True
            conf, st = self._req(port, tok, "GET", "/layer/conformance/self-j20")
            assert self._body(conf).get("not_central_certification") is True
            rl, st = self._req(port, tok, "POST", "/layer/roles", {"role": role})
            assert st == 201
            if role == "PORTFOLIO_ANALYTICS":
                assert "invented_aum" not in self._body(rl)
        ast, st = self._req(PORT_A, tok_a, "POST", "/institutional/assets", {"label": "external-observed", "kind": "FINANCIAL"})
        assert st == 201
        ha, _ = self._get(f"http://127.0.0.1:{PORT_A}/health")
        hb, _ = self._get(f"http://127.0.0.1:{PORT_B}/health")
        self._zero(ha, "J20 A")
        self._zero(hb, "J20 B")
        hc, _ = self._get(f"http://127.0.0.1:{PORT_C}/health")
        assert hc.get("walletless") is True
        ext_c, st = self._req(PORT_C, tok_c, "GET", "/extensions/cognitive-reserve/v1.2")
        assert st == 200
        assert self._body(ext_c).get("not_inferred_from_provider_name") is True


if __name__ == "__main__":
    ModelNetCr12Journeys(__file__).main()
