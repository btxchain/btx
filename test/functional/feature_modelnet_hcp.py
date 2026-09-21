#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
"""HCP/1 process E2E: two independent gateways + walletless connector.

Isolated regtest only. Never production btxd. automatic_spend_atoms stays 0.
Process-tier smoke of the 34 catalog ops on loopback hcpd (finance B).
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
CORE = "111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
RECIPE = "333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333"
VERIFIER = "pkce-verifier-smoke-g"


def pjson(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


class ModelNetHcpTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[
            "-nomodelnet",
            "-modelnet=0",
            "-regtestmatmulbindingheight=2147483647",
            "-regtestmatmulproductdigestheight=2147483647",
            "-regtestmatmulv4height=2147483647",
            "-regtestmatmulrequireproductpayload=0",
        ]]
        self.hcp = []

    def setup_nodes(self):
        self.add_nodes(self.num_nodes, extra_args=self.extra_args)
        self.start_nodes()

    def skip_test_if_missing_module(self):
        self.skip_if_platform_not_posix()
        if self._bin("btx-hcpd") is None:
            raise SkipTest("btx-hcpd not found")
        if self._bin("btx-hosted") is None:
            raise SkipTest("btx-hosted not found")

    def _bin(self, name):
        exeext = self.config["environment"].get("EXEEXT", "")
        builddir = self.config["environment"].get("BUILDDIR")
        cand = Path(builddir) / "bin" / f"{name}{exeext}"
        if cand.is_file() and os.access(cand, os.X_OK):
            return cand
        return None

    def _port_open(self, port):
        s = socket.socket()
        s.settimeout(0.2)
        try:
            s.connect(("127.0.0.1", port))
            s.close()
            return True
        except OSError:
            return False

    def _start_hcp(self, instance, port, finance=False):
        datadir = Path(get_datadir_path(self.options.tmpdir, 0)) / f"hcp-{instance}"
        datadir.mkdir(parents=True, exist_ok=True)
        argv = [
            str(self._bin("btx-hcpd")),
            f"-bind=127.0.0.1:{port}",
            f"-datadir={datadir}",
            f"-instance={instance}",
        ]
        if finance:
            argv.append("-finance=1")
        else:
            argv.append("-walletless")
        log = open(datadir / "hcpd.log", "w", encoding="utf-8")
        proc = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT)
        for _ in range(50):
            if proc.poll() is not None:
                break
            if self._port_open(port):
                self.hcp.append((proc, log))
                return
            time.sleep(0.1)
        proc.terminate()
        log.close()
        raise RuntimeError(f"hcpd {instance} did not bind {port}")

    def _stop_hcp(self):
        for proc, log in self.hcp:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
            log.close()
        self.hcp = []

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

    def _lab_token(self, port, verifier=VERIFIER):
        pkce, _ = self._get(f"http://127.0.0.1:{port}/lab/pkce?verifier={verifier}")
        assert pkce.get("lab_only") is True
        q = urllib.parse.urlencode({
            "account": "account-demo",
            "client_id": "client-demo",
            "redirect": "https://app.example/cb",
            "state": "state-g",
            "challenge": pkce["challenge"],
        })
        auth, _ = self._get(f"http://127.0.0.1:{port}/lab/authorize?{q}")
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
        hdrs = {"Authorization": "Bearer " + token}
        if method == "POST":
            hdrs["DPoP"] = self._dpop(port, method, path, token)
        return hdrs

    def _auth(self, port, method, path, token, body=None, expect_error=False):
        if method == "POST" and body is None:
            body = {}
        return self._http(
            method,
            f"http://127.0.0.1:{port}{path}",
            body,
            headers=self._auth_headers(port, method, path, token),
            expect_error=expect_error,
        )

    def run_test(self):
        self._start_hcp("hcp-a", 18780, finance=False)
        self._start_hcp("hcp-b", 18781, finance=True)
        try:
            with urllib.request.urlopen("http://127.0.0.1:18780/profile", timeout=5) as r:
                a = json.loads(r.read().decode())
            with urllib.request.urlopen("http://127.0.0.1:18781/profile", timeout=5) as r:
                b = json.loads(r.read().decode())
            assert a["object_type"] == "ProviderProfile"
            assert b["object_type"] == "ProviderProfile"
            assert a["body"]["provider_id"]
            hosted = subprocess.check_output([str(self._bin("btx-hosted")), "walletless"], text=True)
            st = json.loads(hosted)
            assert st["walletless"] is True
            assert st["start_wallet"] is False
            assert st["automatic_spend_atoms"] == 0
            # public search (walletless discovery)
            req = urllib.request.Request(
                "http://127.0.0.1:18780/capabilities/search",
                data=b"{}",
                method="POST",
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=5) as r:
                hits = json.loads(r.read().decode())
            assert "hits" in hits
            with urllib.request.urlopen("http://127.0.0.1:18780/health", timeout=5) as r:
                health = json.loads(r.read().decode())
            assert health["ok"] is True
            assert health["automatic_spend_atoms"] == 0
            assert health["walletless"] is True
            with urllib.request.urlopen("http://127.0.0.1:18781/health", timeout=5) as r:
                health_b = json.loads(r.read().decode())
            assert health_b["finance"] is True
            assert health_b["automatic_spend_atoms"] == 0
            with urllib.request.urlopen("http://127.0.0.1:18780/economy/demo", timeout=5) as r:
                econ = json.loads(r.read().decode())
            assert econ.get("anchor_required_for_finance") is True
            rpc = urllib.request.Request("http://127.0.0.1:18780/rpc", data=b"{}", method="POST")
            try:
                urllib.request.urlopen(rpc, timeout=5)
                raise AssertionError("/rpc must 404")
            except urllib.error.HTTPError as e:
                assert e.code == 404
            fin = urllib.request.Request("http://127.0.0.1:18780/finance/intents", data=b"{}", method="POST")
            try:
                urllib.request.urlopen(fin, timeout=5)
                raise AssertionError("walletless finance must fail")
            except urllib.error.HTTPError as e:
                assert e.code >= 400

            # Process-tier 34-op smoke on finance B (unique ids vs journeys).
            B = 18781
            econ34, st = self._get("http://127.0.0.1:18781/economy/smoke-34")
            assert st == 200
            assert econ34.get("anchor_required_for_finance") is True
            pkg, st = self._http("GET", f"http://127.0.0.1:18780/packages/{CORE}")
            assert st == 200
            token = self._lab_token(B)

            en, st = self._auth(B, "POST", "/devices/enroll", token, {"device_id": "device-smoke-g"})
            assert st == 201
            cf, st = self._auth(
                B, "POST", "/devices/device-smoke-g/confirm", token, {"challenge": en["challenge"]}
            )
            assert st == 200
            assert cf["paired"] is True
            ho, st = self._auth(
                B,
                "POST",
                "/handoffs",
                token,
                {"device_id": "device-smoke-g", "package_core_id": CORE, "recipe_id": RECIPE},
            )
            assert st == 201
            hid = ho["body"]["handoff_id"]
            got_ho, st = self._auth(B, "GET", f"/handoffs/{hid}", token)
            assert st == 200
            assert got_ho["object_type"] == "CapabilityHandoff"
            lst, st = self._auth(B, "GET", "/devices/device-smoke-g/handoffs", token)
            assert st == 200
            assert lst.get("outbound_only") is True
            _, st = self._auth(
                B, "POST", "/devices/device-smoke-g/reports", token, {}, expect_error=True
            )
            assert st in (400, 403)
            _, st = self._auth(B, "POST", "/devices/device-smoke-g/revoke", token)
            assert st == 200

            sse, st, ctype = self._raw(
                "GET",
                "http://127.0.0.1:18781/events/stream",
                headers={"Authorization": "Bearer " + token},
            )
            assert st == 200
            assert ctype == "text/event-stream" or (ctype or "").split(";")[0].strip() == "text/event-stream"
            assert sse.startswith("event: hcp")
            ev, st = self._auth(B, "GET", "/events", token)
            assert st == 200
            assert ev.get("at_least_once") is True

            dr, st = self._auth(B, "POST", "/research/drafts", token, {})
            assert st == 201
            did = dr["draft_id"]
            badv, st = self._auth(
                B,
                "POST",
                f"/research/drafts/{did}/validate",
                token,
                {"fail": True},
                expect_error=True,
            )
            assert st == 400
            assert badv.get("valid") is False
            _, st = self._auth(B, "POST", f"/research/drafts/{did}/validate", token, {})
            assert st == 200
            _, st = self._auth(B, "POST", f"/research/drafts/{did}/publish", token, {})
            assert st == 202
            dr2, st = self._auth(B, "POST", "/research/drafts", token, {})
            assert st == 201
            did2 = dr2["draft_id"]
            _, st = self._auth(
                B, "POST", f"/research/drafts/{did2}/publish", token, {}, expect_error=True
            )
            assert st == 400
            subm, st = self._get("http://127.0.0.1:18781/research/submissions/sub-smoke-g")
            assert st == 200
            assert subm.get("state") == "UNKNOWN"

            ex, st = self._auth(B, "POST", "/exports", token, {})
            assert st == 202
            eid = ex["export_id"]
            xg, st = self._auth(B, "GET", f"/exports/{eid}", token)
            assert st == 200
            assert xg.get("ready") is False
            assert xg.get("retrieved") is True
            _, st = self._auth(
                B, "GET", "/exports/export-missing-smoke-g", token, expect_error=True
            )
            assert st == 404

            pol, st = self._auth(
                B,
                "POST",
                "/policies",
                token,
                {"policy_id": "policy-smoke-g", "lifetime_principal_atoms": "100000", "allowed_actions": ["FUND_RELEASE"]},
            )
            assert st == 201
            pg, st = self._auth(B, "GET", "/policies/policy-smoke-g", token)
            assert st == 200
            assert pg.get("policy_id") == "policy-smoke-g"
            _, st = self._auth(B, "POST", "/policies/policy-smoke-g/revoke", token)
            assert st == 200
            subo, st = self._auth(B, "POST", "/subscriptions", token, {})
            assert st == 201
            sid = subo["subscription_id"]
            rv, st = self._auth(B, "POST", f"/subscriptions/{sid}/revoke", token)
            assert st == 200
            assert rv.get("revoked") is True

            quote, st = self._auth(B, "POST", "/finance/quotes", token, {})
            assert st == 201
            created, st = self._auth(
                B, "POST", "/finance/intents", token, {"client_operation_id": "smoke-g-intent"}
            )
            assert st == 201
            iid = created["body"]["intent_id"]
            _, st = self._auth(B, "POST", f"/finance/intents/{iid}/authorize", token)
            assert st == 200
            sub, st = self._auth(B, "POST", f"/finance/intents/{iid}/submit", token)
            assert st in (200, 202)
            stt, st = self._auth(B, "GET", f"/finance/intents/{iid}", token)
            assert st == 200
            assert stt.get("runtime_ready") is False
            bals, st = self._auth(B, "GET", "/treasury/balances", token)
            assert st == 200
            rec, st = self._auth(B, "GET", f"/finance/intents/{iid}/receipts", token)
            assert st == 200
            assert "ids" in rec
            rid = sub.get("receipt_id") or (rec["ids"][0] if rec["ids"] else None)
            assert rid
            rec1, st = self._auth(B, "GET", f"/finance/receipts/{rid}", token)
            assert st == 200
            assert rec1.get("spv_claimed") is False
            _, st = self._auth(B, "POST", f"/finance/intents/{iid}/cancel", token)
            assert st in (200, 202, 400, 409)
            opg, st = self._auth(B, "GET", f"/operations/{iid}", token)
            assert st == 200
            assert opg.get("operation_id") == iid
        finally:
            self._stop_hcp()


if __name__ == "__main__":
    ModelNetHcpTest(__file__).main()
