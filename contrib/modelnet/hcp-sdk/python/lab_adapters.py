# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""SIMULATION_ONLY partner adapters for HCP/1 lab harnesses.

Not a wallet, HSM, CEX connector, or live credential store. Signing and
broadcast timeouts stay Certainty.UNKNOWN: never auto-submit, never construct
replacement spends, never fail over to another venue while UNKNOWN.
automatic_spend_atoms is always 0. EVM_GENERIC and DisabledProductionSigner
remain CUSTODY_UNSUPPORTED.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from threading import RLock
from typing import Any
from urllib.parse import urlparse

_REF = Path(__file__).resolve().parents[2] / "hcp-reference"
if str(_REF) not in sys.path:
    sys.path.insert(0, str(_REF))

from adapter_contracts import (  # noqa: E402
    AUTOMATIC_SPEND_ATOMS,
    AdapterError,
    Caller,
    Certainty,
    DisabledProductionSigner,
    EVIDENCE_SIMULATION_ONLY,
    EffectOutcome,
    NativeFamily,
)

_LIVE_KW = frozenset(
    {
        "api_key",
        "api_secret",
        "client_secret",
        "hsm_pin",
        "hsm_endpoint",
        "wallet_seed",
        "private_key",
        "live_credentials",
        "production_token",
        "aws_secret_access_key",
        "oauth_refresh_token",
        "coinbase_api_key",
        "binance_secret",
    }
)
_LIVE_TOKEN_PREFIXES = (
    "eyj",
    "sk_live",
    "sk-",
    "akia",
    "bearer ",
    "dpop ",
)
_BLOCKED_WEBHOOK_HOSTS = frozenset(
    {
        "localhost",
        "localhost.localdomain",
        "metadata.google.internal",
        "metadata",
        "instance-data",
        "ip6-localhost",
        "ip6-loopback",
    }
)
_WEBHOOK_ALLOWLIST = frozenset({"hooks.lab.example"})
_ALLOWED_AUDIENCES = frozenset({"hcp.lab", "hcp.catalog", "hcp.finance", "hcp.events"})
_ALLOWED_ACTIONS = frozenset({"FUND_RELEASE", "FUND_BOUNTY", "CLAIM", "REFUND", "CONVERT"})
_ALLOWED_EXPORT = frozenset(
    {
        "operation_id",
        "certainty",
        "intent_digest",
        "amounts",
        "custody_obligations",
        "evidence",
        "automatic_spend_atoms",
        "state",
        "receipt_ref",
    }
)
_ATOM_RE = re.compile(r"0|[1-9][0-9]{0,19}")


def _atoms(value: str) -> int:
    if not isinstance(value, str) or not _ATOM_RE.fullmatch(value):
        raise AdapterError("ATOM_ENCODING", "atom amounts are unsigned decimal strings")
    n = int(value)
    if n > 2**63 - 1:
        raise AdapterError("AMOUNT_RANGE")
    return n


def reject_live_credentials(**kwargs: Any) -> None:
    """Lab adapters never accept production/live credential material."""
    for key, val in kwargs.items():
        if key in _LIVE_KW and val:
            raise AdapterError("LIVE_CREDENTIALS_REJECTED", f"refusing {key}")
        if isinstance(val, str) and val.strip().lower().startswith(_LIVE_TOKEN_PREFIXES):
            raise AdapterError("LIVE_CREDENTIALS_REJECTED", f"live token in {key}")
    evidence = kwargs.get("evidence", EVIDENCE_SIMULATION_ONLY)
    if evidence != EVIDENCE_SIMULATION_ONLY:
        raise AdapterError("LIVE_CREDENTIALS_REJECTED", "lab evidence is SIMULATION_ONLY")
    if kwargs.get("production") or kwargs.get("simulation_only") is False:
        raise AdapterError("LIVE_CREDENTIALS_REJECTED", "production mode is not a lab adapter")
    env = kwargs.get("environment")
    if isinstance(env, str) and env.upper() in {"MAINNET", "PRODUCTION", "LIVE"}:
        raise AdapterError("LIVE_CREDENTIALS_REJECTED", "live environment refused")


def reject_live_token(token_reference: str) -> None:
    if not isinstance(token_reference, str) or not token_reference:
        raise AdapterError("AUTH_REQUIRED", "token_reference required")
    lowered = token_reference.strip().lower()
    if lowered.startswith(_LIVE_TOKEN_PREFIXES) or lowered.count(".") == 2 and lowered.startswith("eyj"):
        raise AdapterError("LIVE_CREDENTIALS_REJECTED", "live token material")
    if "sk_live" in lowered or "akia" in lowered:
        raise AdapterError("LIVE_CREDENTIALS_REJECTED", "live token material")


def _host_ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    text = host.strip("[]")
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        pass
    if text.isdigit():
        try:
            return ipaddress.ip_address(int(text))
        except ValueError:
            return None
    if text.lower().startswith("0x"):
        try:
            return ipaddress.ip_address(int(text, 16))
        except ValueError:
            return None
    return None


def reject_webhook_url(destination_url: str, *, allowlist: frozenset[str] = _WEBHOOK_ALLOWLIST) -> None:
    """SSRF-closed webhook enrollment: HTTPS + allowlist; no private/metadata dests."""
    if not isinstance(destination_url, str) or not destination_url.strip():
        raise AdapterError("SSRF_REJECTED", "empty destination")
    parsed = urlparse(destination_url)
    if parsed.scheme.lower() != "https":
        raise AdapterError("SSRF_REJECTED", "https required")
    if parsed.username is not None or parsed.password is not None:
        raise AdapterError("SSRF_REJECTED", "userinfo forbidden")
    host = (parsed.hostname or "").lower().rstrip(".")
    if not host:
        raise AdapterError("SSRF_REJECTED", "no host")
    if host in _BLOCKED_WEBHOOK_HOSTS or host.endswith(".internal") or host.endswith(".localhost"):
        raise AdapterError("SSRF_REJECTED", "blocked host")
    if "127.0.0.1" in host or "169.254.169.254" in host or host.startswith("metadata."):
        raise AdapterError("SSRF_REJECTED", "blocked host")
    ip = _host_ip(host)
    if ip is not None:
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            raise AdapterError("SSRF_REJECTED", "private destination")
    parts = host.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        try:
            ip = ipaddress.ip_address(host)
            if ip.is_private or ip.is_loopback or ip.is_link_local:
                raise AdapterError("SSRF_REJECTED", "private destination")
        except ValueError:
            pass
    if host not in allowlist:
        raise AdapterError("SSRF_REJECTED", "destination not allowlisted")


def _sim_ref(kind: str, seed: str) -> str:
    digest = hashlib.sha256(f"{kind}:{seed}".encode()).hexdigest()[:24]
    return f"SIMULATION_ONLY-{kind}-{digest}"


def _family_from_bytes(blob: bytes) -> str | None:
    if b"EVM_GENERIC" in blob or blob.startswith(b"EVM"):
        return NativeFamily.EVM_GENERIC.value
    try:
        obj = json.loads(blob.decode("utf-8"))
    except (ValueError, UnicodeError):
        return None
    if isinstance(obj, dict):
        fam = obj.get("native_family") or obj.get("family")
        if isinstance(fam, str):
            return fam
    return None


@dataclass
class LabFaults:
    sign_timeout: bool = False
    broadcast_timeout: bool = False
    reserve_timeout: bool = False
    quote_timeout: bool = False
    observe_timeout: bool = False
    oneshot: bool = True

    def take(self, name: str) -> bool:
        armed = bool(getattr(self, name))
        if armed and self.oneshot:
            setattr(self, name, False)
        return armed


@dataclass
class _Op:
    operation_id: str
    kind: str
    certainty: Certainty
    result_ref: str | None
    fence: int
    intent_digest: str | None = None
    total_atoms: str | None = None
    actual_atoms: str | None = None
    transaction: bytes | None = None
    signed_bytes: bytes | None = None
    quote_ref: str | None = None
    venue: str = "lab-venue-a"
    hold_atoms: int = 0
    unknown: bool = False
    event: dict[str, Any] | None = None


@dataclass
class LabStore:
    lock: RLock = field(default_factory=RLock)
    ops: dict[str, _Op] = field(default_factory=dict)
    by_digest: dict[str, str] = field(default_factory=dict)
    fences: dict[str, int] = field(default_factory=dict)
    unknown_ops: set[str] = field(default_factory=set)
    quotes: dict[str, dict[str, Any]] = field(default_factory=dict)
    packages: dict[str, bytes] = field(default_factory=dict)
    terms: dict[str, bytes] = field(default_factory=dict)
    events: dict[str, str] = field(default_factory=dict)
    webhooks: dict[str, str] = field(default_factory=dict)
    observed: dict[str, dict[str, Any]] = field(default_factory=dict)
    venues_attempted: list[str] = field(default_factory=list)
    auto_submit_attempts: int = 0
    replacement_attempts: int = 0
    failover_attempts: int = 0

    def require_fence(self, operation_id: str, fence: int, *, claim: bool) -> None:
        if not isinstance(fence, int) or fence < 0:
            raise AdapterError("FENCE_CONFLICT", "fence must be a non-negative int")
        current = self.fences.get(operation_id)
        if current is None:
            if claim:
                self.fences[operation_id] = fence
            return
        if current != fence:
            if operation_id in self.unknown_ops:
                raise AdapterError("FENCE_CONFLICT", "stale fence cannot mutate during UNKNOWN")
            raise AdapterError("FENCE_CONFLICT", "stale fence")


class LabLedgerAdapter:
    def __init__(self, store: LabStore, faults: LabFaults):
        self._store = store
        self._faults = faults

    def reserve(self, caller: Caller, intent_digest: str, total_atoms: str, fence: int) -> EffectOutcome:
        _atoms(total_atoms)
        if not intent_digest:
            raise AdapterError("IDEMPOTENCY_CONFLICT", "intent_digest required")
        with self._store.lock:
            key = f"{caller.tenant}/{caller.account}/{intent_digest}"
            existing_id = self._store.by_digest.get(key)
            if existing_id is not None:
                prev = self._store.ops[existing_id]
                if prev.total_atoms != total_atoms:
                    raise AdapterError("IDEMPOTENCY_CONFLICT", "same digest different amount")
                self._store.require_fence(existing_id, fence, claim=False)
                return EffectOutcome(prev.operation_id, prev.certainty, prev.result_ref)
            operation_id = _sim_ref("reserve", key)
            self._store.require_fence(operation_id, fence, claim=True)
            timeout = self._faults.take("reserve_timeout")
            certainty = Certainty.UNKNOWN if timeout else Certainty.APPLIED
            op = _Op(
                operation_id=operation_id,
                kind="reserve",
                certainty=certainty,
                result_ref=None if timeout else operation_id,
                fence=fence,
                intent_digest=intent_digest,
                total_atoms=total_atoms,
                hold_atoms=_atoms(total_atoms),
                unknown=timeout,
            )
            self._store.ops[operation_id] = op
            self._store.by_digest[key] = operation_id
            if timeout:
                self._store.unknown_ops.add(operation_id)
            return EffectOutcome(operation_id, certainty, op.result_ref)

    def lookup(self, operation_id: str) -> EffectOutcome:
        with self._store.lock:
            op = self._store.ops.get(operation_id)
            if op is None:
                return EffectOutcome(operation_id, Certainty.NOT_APPLIED, None)
            return EffectOutcome(op.operation_id, op.certainty, op.result_ref)

    def settle(self, operation_id: str, actual_atoms: str, fence: int) -> EffectOutcome:
        _atoms(actual_atoms)
        with self._store.lock:
            op = self._store.ops.get(operation_id)
            if op is None:
                raise AdapterError("NOT_FOUND", "no reservation")
            self._store.require_fence(operation_id, fence, claim=False)
            if op.certainty is Certainty.UNKNOWN or operation_id in self._store.unknown_ops:
                raise AdapterError("RECONCILIATION_REQUIRED", "cannot settle while UNKNOWN")
            if op.kind != "reserve" or op.certainty is not Certainty.APPLIED:
                raise AdapterError("STATE_CONFLICT", "settle requires an applied reserve")
            if _atoms(actual_atoms) > _atoms(op.total_atoms or "0"):
                raise AdapterError("AMOUNT_RANGE", "actual exceeds reserved")
            op.actual_atoms = actual_atoms
            op.hold_atoms = 0
            op.kind = "settled"
            op.result_ref = _sim_ref("settle", operation_id)
            return EffectOutcome(operation_id, Certainty.APPLIED, op.result_ref)

    def held_atoms(self, operation_id: str) -> int:
        with self._store.lock:
            op = self._store.ops.get(operation_id)
            return 0 if op is None else op.hold_atoms


class EvmGenericCustody:
    """Advertised generic EVM support is not a BTX native family."""

    def inspect_native_template(self, template: bytes, terms: bytes) -> dict:
        raise AdapterError("CUSTODY_UNSUPPORTED", "EVM_GENERIC cannot sign BTX native templates")

    def sign_exact(self, *args: Any, **kwargs: Any) -> EffectOutcome:
        raise AdapterError("CUSTODY_UNSUPPORTED", "EVM_GENERIC cannot sign BTX native templates")

    def lookup_signature(self, operation_id: str) -> EffectOutcome:
        raise AdapterError("CUSTODY_UNSUPPORTED", "EVM_GENERIC cannot sign BTX native templates")


class LabCustodyAdapter:
    def __init__(self, store: LabStore, faults: LabFaults, family: NativeFamily):
        self._store = store
        self._faults = faults
        self._family = family

    def inspect_native_template(self, template: bytes, terms: bytes) -> dict:
        detected = _family_from_bytes(template) or _family_from_bytes(terms)
        if self._family is NativeFamily.EVM_GENERIC or detected == NativeFamily.EVM_GENERIC.value:
            raise AdapterError("CUSTODY_UNSUPPORTED", "EVM_GENERIC cannot sign BTX native templates")
        if self._family is NativeFamily.DISABLED:
            raise AdapterError("CUSTODY_UNSUPPORTED", "supply independently tested native signer")
        return {
            "supported": True,
            "native_family": NativeFamily.BTX_NATIVE_TEMPLATES.value,
            "automatic_spend_atoms": AUTOMATIC_SPEND_ATOMS,
            "evidence": EVIDENCE_SIMULATION_ONLY,
            "broadcast": False,
        }

    def sign_exact(
        self, operation_id: str, approved_digest: str, transaction: bytes, fence: int
    ) -> EffectOutcome:
        if not operation_id or not approved_digest:
            raise AdapterError("IDEMPOTENCY_CONFLICT", "operation_id and approved_digest required")
        if not isinstance(transaction, (bytes, bytearray)) or not transaction:
            raise AdapterError("TERMS_CHANGED", "exact transaction bytes required")
        detected = _family_from_bytes(bytes(transaction))
        if self._family is NativeFamily.EVM_GENERIC or detected == NativeFamily.EVM_GENERIC.value:
            raise AdapterError("CUSTODY_UNSUPPORTED", "EVM_GENERIC cannot sign BTX native templates")
        with self._store.lock:
            self._store.require_fence(operation_id, fence, claim=True)
            existing = self._store.ops.get(operation_id)
            if existing is not None and existing.transaction is not None:
                if existing.transaction != bytes(transaction):
                    raise AdapterError(
                        "REPLACEMENT_SPEND_FORBIDDEN",
                        "never construct replacement spends",
                    )
                return EffectOutcome(existing.operation_id, existing.certainty, existing.result_ref)
            timeout = self._faults.take("sign_timeout")
            signed = b"SIMULATION_ONLY-SIG:" + bytes(transaction)
            certainty = Certainty.UNKNOWN if timeout else Certainty.APPLIED
            op = existing or _Op(
                operation_id=operation_id,
                kind="sign",
                certainty=certainty,
                result_ref=None,
                fence=fence,
            )
            op.kind = "sign"
            op.fence = fence
            op.transaction = bytes(transaction)
            op.signed_bytes = signed
            op.intent_digest = approved_digest
            op.certainty = certainty
            op.unknown = timeout
            op.result_ref = None if timeout else _sim_ref("sig", operation_id)
            self._store.ops[operation_id] = op
            if timeout:
                self._store.unknown_ops.add(operation_id)
            else:
                self._store.unknown_ops.discard(operation_id)
            return EffectOutcome(operation_id, certainty, op.result_ref)

    def lookup_signature(self, operation_id: str) -> EffectOutcome:
        with self._store.lock:
            op = self._store.ops.get(operation_id)
            if op is None or op.signed_bytes is None:
                return EffectOutcome(operation_id, Certainty.NOT_APPLIED, None)
            if op.unknown or op.certainty is Certainty.UNKNOWN:
                # Timeout after apply: bytes exist locally; lookup proves the same
                # signing operation, not a new spend. Certainty stays UNKNOWN until
                # reconcile; this is not NOT_APPLIED and not a safe failure.
                return EffectOutcome(operation_id, Certainty.UNKNOWN, None)
            return EffectOutcome(op.operation_id, op.certainty, op.result_ref)

    def broadcast_exact(self, operation_id: str, signed_transaction: bytes, fence: int) -> EffectOutcome:
        """Lab-only dispatch. Timeouts stay UNKNOWN; never a second spend."""
        with self._store.lock:
            op = self._store.ops.get(operation_id)
            if op is None:
                raise AdapterError("NOT_FOUND", "no signing operation")
            self._store.require_fence(operation_id, fence, claim=False)
            if op.certainty is Certainty.UNKNOWN or operation_id in self._store.unknown_ops:
                raise AdapterError("UNKNOWN_NOT_SAFE_FAILURE", "never auto-submit while UNKNOWN")
            if op.signed_bytes is None:
                raise AdapterError("NOT_FOUND", "no signed bytes")
            if bytes(signed_transaction) != op.signed_bytes:
                raise AdapterError("REPLACEMENT_SPEND_FORBIDDEN", "never construct replacement spends")
            timeout = self._faults.take("broadcast_timeout")
            txid = _sim_ref("tx", operation_id)
            op.kind = "broadcast"
            if timeout:
                op.certainty = Certainty.UNKNOWN
                op.unknown = True
                op.result_ref = None
                self._store.unknown_ops.add(operation_id)
                self._store.observed[txid] = {
                    "status": "UNKNOWN",
                    "certainty": Certainty.UNKNOWN.value,
                    "transaction_id": txid,
                    "confirmed": False,
                    "automatic_spend_atoms": AUTOMATIC_SPEND_ATOMS,
                    "evidence": EVIDENCE_SIMULATION_ONLY,
                }
                return EffectOutcome(operation_id, Certainty.UNKNOWN, None)
            op.certainty = Certainty.APPLIED
            op.unknown = False
            op.result_ref = txid
            self._store.unknown_ops.discard(operation_id)
            self._store.observed[txid] = {
                "status": "BROADCAST",
                "certainty": Certainty.APPLIED.value,
                "transaction_id": txid,
                "confirmed": False,
                "automatic_spend_atoms": AUTOMATIC_SPEND_ATOMS,
                "evidence": EVIDENCE_SIMULATION_ONLY,
            }
            return EffectOutcome(operation_id, Certainty.APPLIED, txid)


class LabChainObserver:
    def __init__(self, store: LabStore, faults: LabFaults):
        self._store = store
        self._faults = faults

    def observe(self, transaction_id: str, outpoints: list[str]) -> dict:
        with self._store.lock:
            if self._faults.take("observe_timeout"):
                return {
                    "status": "UNKNOWN",
                    "certainty": Certainty.UNKNOWN.value,
                    "transaction_id": transaction_id,
                    "outpoints": list(outpoints),
                    "confirmed": False,
                    "automatic_spend_atoms": AUTOMATIC_SPEND_ATOMS,
                    "evidence": EVIDENCE_SIMULATION_ONLY,
                }
            known = self._store.observed.get(transaction_id)
            if known is not None:
                out = dict(known)
                out["outpoints"] = list(outpoints)
                out["automatic_spend_atoms"] = AUTOMATIC_SPEND_ATOMS
                return out
            return {
                "status": "ABSENT",
                "certainty": Certainty.NOT_APPLIED.value,
                "transaction_id": transaction_id,
                "outpoints": list(outpoints),
                "confirmed": False,
                "automatic_spend_atoms": AUTOMATIC_SPEND_ATOMS,
                "evidence": EVIDENCE_SIMULATION_ONLY,
            }


class LabIdentityAdapter:
    def verify_caller(self, token_reference: str, audience: str, sender_proof: bytes) -> Caller:
        reject_live_token(token_reference)
        if not token_reference.startswith("lab:"):
            raise AdapterError("AUTH_REQUIRED", "lab identity accepts only lab: references")
        if audience not in _ALLOWED_AUDIENCES:
            raise AdapterError("SCOPE_DENIED", "unexpected audience")
        parts = token_reference.split(":")
        if len(parts) < 4:
            raise AdapterError("AUTH_REQUIRED", "lab:tenant:account:principal")
        _, tenant, account, principal, *rest = parts
        scopes = frozenset(rest) if rest else frozenset({"catalog:read"})
        return Caller(tenant=tenant, account=account, principal=principal, scopes=scopes)


class LabEligibilityAdapter:
    def decide(self, caller: Caller, action: str, terms_id: str, policy_version: str) -> dict:
        if not policy_version:
            return {
                "allowed": False,
                "reason": "POLICY_DENIED",
                "policy_version": policy_version,
                "automatic_spend_atoms": AUTOMATIC_SPEND_ATOMS,
                "evidence": EVIDENCE_SIMULATION_ONLY,
            }
        if action not in _ALLOWED_ACTIONS:
            return {
                "allowed": False,
                "reason": "ACTION_DENIED",
                "policy_version": policy_version,
                "automatic_spend_atoms": AUTOMATIC_SPEND_ATOMS,
                "evidence": EVIDENCE_SIMULATION_ONLY,
            }
        if "intents:submit" not in caller.scopes and action in {"FUND_RELEASE", "FUND_BOUNTY"}:
            return {
                "allowed": False,
                "reason": "SCOPE_DENIED",
                "policy_version": policy_version,
                "automatic_spend_atoms": AUTOMATIC_SPEND_ATOMS,
                "evidence": EVIDENCE_SIMULATION_ONLY,
            }
        return {
            "allowed": True,
            "reason": "OK",
            "policy_version": policy_version,
            "terms_id": terms_id,
            "automatic_spend_atoms": AUTOMATIC_SPEND_ATOMS,
            "evidence": EVIDENCE_SIMULATION_ONLY,
        }


class LabQuoteAdapter:
    def __init__(self, store: LabStore, faults: LabFaults, venue: str = "lab-venue-a"):
        self._store = store
        self._faults = faults
        self._venue = venue

    def firm_conversion_quote(
        self, caller: Caller, source_asset: str, max_source_minor: str, target_btx_atoms: str
    ) -> dict:
        _atoms(max_source_minor)
        _atoms(target_btx_atoms)
        quote_ref = _sim_ref("quote", f"{caller.account}:{source_asset}:{target_btx_atoms}")
        body = {
            "quote_ref": quote_ref,
            "source_asset": source_asset,
            "max_source_minor": max_source_minor,
            "target_btx_atoms": target_btx_atoms,
            "venue": self._venue,
            "automatic_spend_atoms": AUTOMATIC_SPEND_ATOMS,
            "evidence": EVIDENCE_SIMULATION_ONLY,
            "expires_at_ms": "1790000600000",
        }
        with self._store.lock:
            self._store.quotes[quote_ref] = body
        return dict(body)

    def execute_exact_quote(self, caller: Caller, quote_ref: str, operation_id: str) -> EffectOutcome:
        with self._store.lock:
            quote = self._store.quotes.get(quote_ref)
            if quote is None:
                raise AdapterError("QUOTE_EXPIRED", "unknown quote_ref")
            existing = self._store.ops.get(operation_id)
            if existing is not None and existing.kind == "convert":
                if existing.quote_ref != quote_ref:
                    raise AdapterError("IDEMPOTENCY_CONFLICT", "operation already bound")
                return EffectOutcome(existing.operation_id, existing.certainty, existing.result_ref)
            self._store.venues_attempted.append(self._venue)
            timeout = self._faults.take("quote_timeout")
            certainty = Certainty.UNKNOWN if timeout else Certainty.APPLIED
            op = _Op(
                operation_id=operation_id,
                kind="convert",
                certainty=certainty,
                result_ref=None if timeout else _sim_ref("fx", operation_id),
                fence=0,
                quote_ref=quote_ref,
                venue=self._venue,
                unknown=timeout,
            )
            self._store.ops[operation_id] = op
            if timeout:
                self._store.unknown_ops.add(operation_id)
            return EffectOutcome(operation_id, certainty, op.result_ref)

    def lookup_conversion(self, operation_id: str) -> EffectOutcome:
        with self._store.lock:
            op = self._store.ops.get(operation_id)
            if op is None or op.kind != "convert":
                return EffectOutcome(operation_id, Certainty.NOT_APPLIED, None)
            return EffectOutcome(op.operation_id, op.certainty, op.result_ref)


class LabNativeEconomyAdapter:
    def __init__(self, store: LabStore):
        self._store = store
        with self._store.lock:
            self._store.terms.setdefault(
                "lab-terms-release",
                json.dumps(
                    {
                        "terms_id": "lab-terms-release",
                        "native_family": NativeFamily.BTX_NATIVE_TEMPLATES.value,
                        "automatic_spend_atoms": AUTOMATIC_SPEND_ATOMS,
                        "evidence": EVIDENCE_SIMULATION_ONLY,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode(),
            )

    def inspect_terms(self, network_id: str, terms_id: str) -> bytes:
        with self._store.lock:
            blob = self._store.terms.get(terms_id)
            if blob is None:
                raise AdapterError("TERMS_CHANGED", "unknown terms_id")
            return blob

    def prepare_exact(
        self,
        caller: Caller,
        action: str,
        terms_id: str,
        principal_atoms: str,
        fee_cap_atoms: str,
    ) -> dict:
        _atoms(principal_atoms)
        _atoms(fee_cap_atoms)
        self.inspect_terms("lab-regtest", terms_id)
        if action not in _ALLOWED_ACTIONS:
            raise AdapterError("ACTION_DENIED", action)
        return {
            "action": action,
            "terms_id": terms_id,
            "principal_atoms": principal_atoms,
            "fee_cap_atoms": fee_cap_atoms,
            "native_family": NativeFamily.BTX_NATIVE_TEMPLATES.value,
            "automatic_spend_atoms": AUTOMATIC_SPEND_ATOMS,
            "evidence": EVIDENCE_SIMULATION_ONLY,
            "transaction": None,
            "ready_to_sign": True,
        }

    def verify_frozen_transaction(self, transaction: bytes, terms: bytes) -> dict:
        detected = _family_from_bytes(transaction) or _family_from_bytes(terms)
        if detected == NativeFamily.EVM_GENERIC.value:
            raise AdapterError("CUSTODY_UNSUPPORTED", "EVM_GENERIC cannot verify BTX frozen templates")
        return {
            "ok": True,
            "native_family": NativeFamily.BTX_NATIVE_TEMPLATES.value,
            "automatic_spend_atoms": AUTOMATIC_SPEND_ATOMS,
            "evidence": EVIDENCE_SIMULATION_ONLY,
        }


class LabPackageAdapter:
    def __init__(self, store: LabStore):
        self._store = store
        core = "1" * 96
        with self._store.lock:
            self._store.packages.setdefault(
                core,
                json.dumps(
                    {
                        "package_core_id": core,
                        "evidence": EVIDENCE_SIMULATION_ONLY,
                        "automatic_spend_atoms": AUTOMATIC_SPEND_ATOMS,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode(),
            )

    def read_exact_package(self, package_core_id: str, max_bytes: int) -> bytes:
        if max_bytes < 1 or max_bytes > 1_048_576:
            raise AdapterError("STRUCTURAL_LIMIT", "max_bytes outside 1..1048576")
        with self._store.lock:
            blob = self._store.packages.get(package_core_id)
            if blob is None:
                raise AdapterError("PACKAGE_MISMATCH", "unknown package_core_id")
            if len(blob) > max_bytes:
                raise AdapterError("STRUCTURAL_LIMIT", "package exceeds max_bytes")
            return blob

    def search_verified(self, query: str, limit: int, cursor: str | None) -> dict:
        if not 1 <= limit <= 100:
            raise AdapterError("STRUCTURAL_LIMIT", "limit outside 1..100")
        with self._store.lock:
            hits = [
                {"package_core_id": pid, "ranking": "protocol", "sponsored": False}
                for pid in self._store.packages
                if not query or query in pid
            ][:limit]
        return {
            "hits": hits,
            "cursor": None,
            "ranking_is_protocol_fact": True,
            "automatic_spend_atoms": AUTOMATIC_SPEND_ATOMS,
            "evidence": EVIDENCE_SIMULATION_ONLY,
        }


class LabAuditAdapter:
    def __init__(self, store: LabStore):
        self._store = store

    def append_once(self, business_event_id: str, redacted_event: dict) -> EffectOutcome:
        if not business_event_id:
            raise AdapterError("IDEMPOTENCY_CONFLICT", "business_event_id required")
        if not isinstance(redacted_event, dict):
            raise AdapterError("SCHEMA_KEY_INVALID", "redacted_event must be an object")
        for key in redacted_event:
            lowered = str(key).lower()
            if "token" in lowered or "secret" in lowered or "authorization" in lowered:
                raise AdapterError("SCOPE_DENIED", "secrets must not appear in audit events")
        with self._store.lock:
            existing_id = self._store.events.get(business_event_id)
            if existing_id is not None:
                prev = self._store.ops[existing_id]
                if prev.event != redacted_event:
                    raise AdapterError("IDEMPOTENCY_CONFLICT", "same event id different body")
                return EffectOutcome(prev.operation_id, prev.certainty, prev.result_ref)
            operation_id = _sim_ref("audit", business_event_id)
            op = _Op(
                operation_id=operation_id,
                kind="audit",
                certainty=Certainty.APPLIED,
                result_ref=operation_id,
                fence=0,
                event=dict(redacted_event),
            )
            self._store.ops[operation_id] = op
            self._store.events[business_event_id] = operation_id
            return EffectOutcome(operation_id, Certainty.APPLIED, operation_id)

    def enroll_webhook(self, destination_url: str, delivery_id: str) -> EffectOutcome:
        return LabWebhookAdapter(self._store).enroll(destination_url, delivery_id)


class LabWebhookAdapter:
    def __init__(self, store: LabStore):
        self._store = store

    def enroll(self, destination_url: str, delivery_id: str) -> EffectOutcome:
        reject_webhook_url(destination_url)
        if not delivery_id:
            raise AdapterError("IDEMPOTENCY_CONFLICT", "delivery_id required")
        with self._store.lock:
            existing = self._store.webhooks.get(delivery_id)
            if existing is not None and existing != destination_url:
                raise AdapterError("IDEMPOTENCY_CONFLICT", "delivery already bound")
            self._store.webhooks[delivery_id] = destination_url
            operation_id = _sim_ref("hook", delivery_id)
            op = _Op(
                operation_id=operation_id,
                kind="webhook",
                certainty=Certainty.APPLIED,
                result_ref=delivery_id,
                fence=0,
            )
            self._store.ops[operation_id] = op
            return EffectOutcome(operation_id, Certainty.APPLIED, delivery_id)


class LabReportingAdapter:
    def __init__(self, store: LabStore):
        self._store = store

    def export_customer(self, caller: Caller, operation_id: str, include: list[str]) -> dict:
        extra = [item for item in include if item not in _ALLOWED_EXPORT]
        if extra:
            raise AdapterError("SCOPE_DENIED", f"export fields not permitted: {extra}")
        with self._store.lock:
            op = self._store.ops.get(operation_id)
            body: dict[str, Any] = {
                "tenant": caller.tenant,
                "account": caller.account,
                "operation_id": operation_id,
                "automatic_spend_atoms": AUTOMATIC_SPEND_ATOMS,
                "evidence": EVIDENCE_SIMULATION_ONLY,
                "secrets": False,
            }
            if op is None:
                body["certainty"] = Certainty.NOT_APPLIED.value
                return body
            body["certainty"] = op.certainty.value
            body["state"] = op.kind
            if "amounts" in include:
                body["amounts"] = {"total_atoms": op.total_atoms, "actual_atoms": op.actual_atoms}
            if "custody_obligations" in include:
                body["custody_obligations"] = True
            if "receipt_ref" in include:
                body["receipt_ref"] = op.result_ref
            return body


class LabPartnerAdapters:
    """In-process partner set. Default evidence is SIMULATION_ONLY."""

    def __init__(
        self,
        *,
        evidence: str = EVIDENCE_SIMULATION_ONLY,
        native_family: NativeFamily | str = NativeFamily.BTX_NATIVE_TEMPLATES,
        venue: str = "lab-venue-a",
        production: bool = False,
        simulation_only: bool = True,
        environment: str = "REGTEST",
        **kwargs: Any,
    ):
        reject_live_credentials(
            evidence=evidence,
            production=production,
            simulation_only=simulation_only,
            environment=environment,
            **kwargs,
        )
        if isinstance(native_family, str):
            native_family = NativeFamily(native_family)
        self.evidence = EVIDENCE_SIMULATION_ONLY
        self.automatic_spend_atoms = AUTOMATIC_SPEND_ATOMS
        self.native_family = native_family
        self.store = LabStore()
        self.faults = LabFaults()
        self.identity = LabIdentityAdapter()
        self.eligibility = LabEligibilityAdapter()
        self.ledger = LabLedgerAdapter(self.store, self.faults)
        if native_family is NativeFamily.DISABLED:
            self.custody: Any = DisabledProductionSigner()
        elif native_family is NativeFamily.EVM_GENERIC:
            self.custody = EvmGenericCustody()
        else:
            self.custody = LabCustodyAdapter(self.store, self.faults, native_family)
        self.chain = LabChainObserver(self.store, self.faults)
        self.quote = LabQuoteAdapter(self.store, self.faults, venue=venue)
        self.economy = LabNativeEconomyAdapter(self.store)
        self.package = LabPackageAdapter(self.store)
        self.audit = LabAuditAdapter(self.store)
        self.reporting = LabReportingAdapter(self.store)
        self.webhook = LabWebhookAdapter(self.store)

    @classmethod
    def from_config(cls, config: dict[str, Any]) -> LabPartnerAdapters:
        finance = dict(config.get("finance") or {})
        native = dict(config.get("native") or {})
        merged = {
            "evidence": config.get("evidence", EVIDENCE_SIMULATION_ONLY),
            "simulation_only": config.get("simulation_only", True),
            "production": bool(config.get("production")),
            "environment": config.get("environment", "REGTEST"),
            "api_key": config.get("api_key") or finance.get("api_key"),
            "hsm_endpoint": native.get("hsm_endpoint") or finance.get("hsm_endpoint"),
        }
        backend = str(finance.get("custody_backend") or config.get("native_family") or "BTX_NATIVE_TEMPLATES")
        if backend in {"EVM_GENERIC", NativeFamily.EVM_GENERIC.value}:
            family: NativeFamily | str = NativeFamily.EVM_GENERIC
        elif backend in {"DISABLED", "DisabledProductionSigner"}:
            family = NativeFamily.DISABLED
        else:
            family = NativeFamily.BTX_NATIVE_TEMPLATES
        return cls(native_family=family, **merged)

    def auto_submit_finance(self, operation_id: str) -> EffectOutcome:
        self.store.auto_submit_attempts += 1
        with self.store.lock:
            op = self.store.ops.get(operation_id)
            if op is None or op.certainty is Certainty.UNKNOWN or operation_id in self.store.unknown_ops:
                raise AdapterError("UNKNOWN_NOT_SAFE_FAILURE", "never auto-submit while UNKNOWN")
        raise AdapterError("AUTO_SUBMIT_FORBIDDEN", "lab adapters never auto-submit")

    def construct_replacement_spend(self, operation_id: str, new_transaction: bytes) -> EffectOutcome:
        self.store.replacement_attempts += 1
        raise AdapterError("REPLACEMENT_SPEND_FORBIDDEN", "never construct replacement spends")

    def failover_venue(self, operation_id: str, venue: str) -> EffectOutcome:
        self.store.failover_attempts += 1
        with self.store.lock:
            op = self.store.ops.get(operation_id)
            if op is not None and (op.certainty is Certainty.UNKNOWN or operation_id in self.store.unknown_ops):
                raise AdapterError(
                    "VENUE_FAILOVER_FORBIDDEN",
                    "never fail over to another venue while UNKNOWN",
                )
        raise AdapterError("VENUE_FAILOVER_FORBIDDEN", "lab adapters never fail over financial work")

    def broadcast_exact(self, operation_id: str, signed_transaction: bytes, fence: int) -> EffectOutcome:
        if not isinstance(self.custody, LabCustodyAdapter):
            raise AdapterError("CUSTODY_UNSUPPORTED", "no lab native signer")
        return self.custody.broadcast_exact(operation_id, signed_transaction, fence)


def lab_caller(*, scopes: frozenset[str] | None = None) -> Caller:
    return Caller(
        tenant="lab-tenant",
        account="lab-account",
        principal="lab-principal",
        scopes=scopes or frozenset({"catalog:read", "intents:submit", "intents:authorize"}),
    )


__all__ = (
    "EvmGenericCustody",
    "LabAuditAdapter",
    "LabChainObserver",
    "LabCustodyAdapter",
    "LabEligibilityAdapter",
    "LabFaults",
    "LabIdentityAdapter",
    "LabLedgerAdapter",
    "LabNativeEconomyAdapter",
    "LabPackageAdapter",
    "LabPartnerAdapters",
    "LabQuoteAdapter",
    "LabReportingAdapter",
    "LabStore",
    "LabWebhookAdapter",
    "lab_caller",
    "reject_live_credentials",
    "reject_live_token",
    "reject_webhook_url",
)
