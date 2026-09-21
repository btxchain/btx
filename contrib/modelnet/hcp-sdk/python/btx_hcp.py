# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""HCP/1 Python SDK. Decimal atom strings. HTTP 202 is UNKNOWN — never auto-submit.

Not a wallet. Does not call native wallet RPC, sign spends, or set
automatic_spend_atoms away from 0. Typed operations only; no /rpc passthrough.
"""

from __future__ import annotations

import hashlib
import json
import struct
import urllib.error
import urllib.request
from typing import Any

HCP_AUTOMATIC_SPEND_ATOMS = 0

# All 34 catalog operations (src/modelnet/hcp/schemas/rpc-catalog.json).
OPERATIONS = (
    ("getProviderProfile", "GET", "/profile"),
    ("searchCapabilities", "POST", "/capabilities/search"),
    ("getPackage", "GET", "/packages/{package_core_id}"),
    ("getEconomy", "GET", "/economy/{target_id}"),
    ("createHandoff", "POST", "/handoffs"),
    ("getHandoff", "GET", "/handoffs/{handoff_id}"),
    ("enrollDevice", "POST", "/devices/enroll"),
    ("confirmDevice", "POST", "/devices/{device_id}/confirm"),
    ("revokeDevice", "POST", "/devices/{device_id}/revoke"),
    ("getDeviceHandoffs", "GET", "/devices/{device_id}/handoffs"),
    ("reportReadiness", "POST", "/devices/{device_id}/reports"),
    ("getBalances", "GET", "/treasury/balances"),
    ("createFundingQuote", "POST", "/finance/quotes"),
    ("createFinanceIntent", "POST", "/finance/intents"),
    ("getFinanceIntent", "GET", "/finance/intents/{intent_id}"),
    ("authorizeFinanceIntent", "POST", "/finance/intents/{intent_id}/authorize"),
    ("submitFinanceIntent", "POST", "/finance/intents/{intent_id}/submit"),
    ("cancelFinanceIntent", "POST", "/finance/intents/{intent_id}/cancel"),
    ("getFinanceReceipts", "GET", "/finance/intents/{intent_id}/receipts"),
    ("getFinanceReceipt", "GET", "/finance/receipts/{receipt_id}"),
    ("createAccountPolicy", "POST", "/policies"),
    ("getAccountPolicy", "GET", "/policies/{policy_id}"),
    ("revokeAccountPolicy", "POST", "/policies/{policy_id}/revoke"),
    ("createSubscription", "POST", "/subscriptions"),
    ("revokeSubscription", "POST", "/subscriptions/{subscription_id}/revoke"),
    ("getEvents", "GET", "/events"),
    ("streamEvents", "GET", "/events/stream"),
    ("createExport", "POST", "/exports"),
    ("getExport", "GET", "/exports/{export_id}"),
    ("createResearchDraft", "POST", "/research/drafts"),
    ("validateResearchDraft", "POST", "/research/drafts/{draft_id}/validate"),
    ("publishResearchDraft", "POST", "/research/drafts/{draft_id}/publish"),
    ("getResearchSubmission", "GET", "/research/submissions/{submission_id}"),
    ("getOperation", "GET", "/operations/{operation_id}"),
)


class HcpError(RuntimeError):
    def __init__(self, code: str, message: str, status: int = 0):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.status = status
        self.unknown = status == 202


def canonical_body(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode(
        "utf-8"
    )


def body_id(kind: str, body: dict) -> str:
    b = canonical_body(body)
    return hashlib.sha384(f"BTX/HCP/{kind}/v1".encode() + b"\0" + struct.pack("<Q", len(b)) + b).hexdigest()


def pjson1(value: dict | None) -> bytes | None:
    if value is None:
        return None
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode(
        "utf-8"
    )


class HcpClient:
    def __init__(self, base: str, access_token: str | None = None, dpop: str | None = None):
        self.base = base.rstrip("/")
        self.access_token = access_token
        self.dpop = dpop
        self.automatic_spend_atoms = HCP_AUTOMATIC_SPEND_ATOMS

    def _req(self, method: str, path: str, body: dict | None = None, *, binary: bool = False) -> Any:
        data = pjson1(body)
        headers = {"Accept": "application/json"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        if self.access_token:
            headers["Authorization"] = "Bearer " + self.access_token
        if self.dpop:
            headers["DPoP"] = self.dpop
        req = urllib.request.Request(self.base + path, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                raw = r.read()
                if binary:
                    return raw
                if r.status == 202:
                    # UNKNOWN / accepted async — never auto-submit.
                    return json.loads(raw.decode()) if raw else {"status": 202, "unknown": True}
                return json.loads(raw.decode()) if raw else {}
        except urllib.error.HTTPError as e:
            payload = e.read().decode()
            raise HcpError("HTTP", payload, e.code) from e

    def get_profile(self) -> dict:
        return self._req("GET", "/profile")

    def search(self, q: str | None = None) -> dict:
        body: dict[str, Any] = {"q": q or ""}
        return self._req("POST", "/capabilities/search", body)

    def get_package(self, package_core_id: str) -> bytes:
        return self._req("GET", "/packages/" + package_core_id, binary=True)

    def get_economy(self, target_id: str) -> dict:
        return self._req("GET", "/economy/" + target_id)

    def create_handoff(self, device_id: str, package_core_id: str, recipe_id: str, client_operation_id: str | None = None) -> dict:
        body = {
            "device_id": device_id,
            "package_core_id": package_core_id,
            "recipe_id": recipe_id,
        }
        if client_operation_id:
            body["client_operation_id"] = client_operation_id
        return self._req("POST", "/handoffs", body)

    def get_handoff(self, handoff_id: str) -> dict:
        return self._req("GET", "/handoffs/" + handoff_id)

    def enroll_device(self, device_id: str, platform: str = "linux") -> dict:
        return self._req("POST", "/devices/enroll", {"device_id": device_id, "platform": platform})

    def confirm_device(self, device_id: str, challenge: str) -> dict:
        return self._req("POST", f"/devices/{device_id}/confirm", {"challenge": challenge})

    def revoke_device(self, device_id: str) -> dict:
        return self._req("POST", f"/devices/{device_id}/revoke", {})

    def get_device_handoffs(self, device_id: str) -> dict:
        return self._req("GET", f"/devices/{device_id}/handoffs")

    def report_readiness(self, device_id: str, envelope: dict) -> dict:
        return self._req("POST", f"/devices/{device_id}/reports", envelope)

    def get_balances(self) -> dict:
        return self._req("GET", "/treasury/balances")

    def create_funding_quote(self, body: dict | None = None) -> dict:
        return self._req("POST", "/finance/quotes", body or {})

    def create_intent(self, body: dict) -> dict:
        return self._req("POST", "/finance/intents", body)

    def get_finance_intent(self, intent_id: str) -> dict:
        return self._req("GET", "/finance/intents/" + intent_id)

    def authorize_finance_intent(self, intent_id: str, body: dict | None = None) -> dict:
        return self._req("POST", f"/finance/intents/{intent_id}/authorize", body or {})

    def submit_finance_intent(self, intent_id: str, body: dict | None = None) -> dict:
        # Caller must poll; this method does not retry on 202.
        return self._req("POST", f"/finance/intents/{intent_id}/submit", body or {})

    def cancel_finance_intent(self, intent_id: str, body: dict | None = None) -> dict:
        return self._req("POST", f"/finance/intents/{intent_id}/cancel", body or {})

    def get_finance_receipts(self, intent_id: str) -> dict:
        return self._req("GET", f"/finance/intents/{intent_id}/receipts")

    def get_finance_receipt(self, receipt_id: str) -> dict:
        return self._req("GET", "/finance/receipts/" + receipt_id)

    def create_account_policy(self, body: dict) -> dict:
        return self._req("POST", "/policies", body)

    def get_account_policy(self, policy_id: str) -> dict:
        return self._req("GET", "/policies/" + policy_id)

    def revoke_account_policy(self, policy_id: str) -> dict:
        return self._req("POST", f"/policies/{policy_id}/revoke", {})

    def create_subscription(self, body: dict | None = None) -> dict:
        return self._req("POST", "/subscriptions", body or {})

    def revoke_subscription(self, subscription_id: str) -> dict:
        return self._req("POST", f"/subscriptions/{subscription_id}/revoke", {})

    def get_events(self) -> dict:
        return self._req("GET", "/events")

    def stream_events(self) -> dict:
        return self._req("GET", "/events/stream")

    def create_export(self, body: dict | None = None) -> dict:
        return self._req("POST", "/exports", body or {})

    def get_export(self, export_id: str) -> dict:
        return self._req("GET", "/exports/" + export_id)

    def create_research_draft(self, body: dict | None = None) -> dict:
        return self._req("POST", "/research/drafts", body or {})

    def validate_research_draft(self, draft_id: str) -> dict:
        return self._req("POST", f"/research/drafts/{draft_id}/validate", {})

    def publish_research_draft(self, draft_id: str, body: dict | None = None) -> dict:
        return self._req("POST", f"/research/drafts/{draft_id}/publish", body or {})

    def get_research_submission(self, submission_id: str) -> dict:
        return self._req("GET", "/research/submissions/" + submission_id)

    def poll_operation(self, operation_id: str) -> dict:
        return self._req("GET", "/operations/" + operation_id)

    def get_operation(self, operation_id: str) -> dict:
        return self.poll_operation(operation_id)
