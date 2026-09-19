# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Typed partner-adapter test harness. SIMULATION_ONLY; no live credentials.

Wraps lab implementations of Ledger, Custody, ChainObserver, Identity,
Eligibility, Quote, NativeEconomy, Package, Audit and Reporting. Signing and
broadcast timeouts stay Certainty.UNKNOWN. The executor never auto-submits,
never constructs replacement spends, and never fails over to another venue
while UNKNOWN.
"""
from __future__ import annotations

import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_SDK_PY = _HERE.parent / "hcp-sdk" / "python"
for _p in (_HERE, _SDK_PY):
    _s = str(_p)
    if _s not in sys.path:
        sys.path.insert(0, _s)

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
from lab_adapters import (  # noqa: E402
    EvmGenericCustody,
    LabPartnerAdapters,
    lab_caller,
    reject_webhook_url,
)


class LabExecutor:
    """Create → reserve → inspect/sign → persist → broadcast.

    A timeout is UNKNOWN, not a safe failure. Holds stay until reconcile.
    """

    def __init__(self, lab: LabPartnerAdapters):
        self.lab = lab
        self.submitted = 0
        self.broadcasts = 0

    def reserve_sign_broadcast(
        self,
        caller: Caller,
        intent_digest: str,
        total_atoms: str,
        fence: int,
        transaction: bytes,
        approved_digest: str,
    ) -> EffectOutcome:
        reserved = self.lab.ledger.reserve(caller, intent_digest, total_atoms, fence)
        if reserved.certainty is Certainty.UNKNOWN:
            return reserved
        if not isinstance(self.lab.custody, (DisabledProductionSigner, EvmGenericCustody)):
            inspected = self.lab.custody.inspect_native_template(transaction, transaction)
            if inspected.get("automatic_spend_atoms") != AUTOMATIC_SPEND_ATOMS:
                raise AdapterError("AUTO_SUBMIT_FORBIDDEN", "nonzero automatic spend")
        signed = self.lab.custody.sign_exact(reserved.operation_id, approved_digest, transaction, fence)
        if signed.certainty is Certainty.UNKNOWN:
            return signed
        self.submitted += 1
        signed_bytes = self.lab.store.ops[reserved.operation_id].signed_bytes
        if signed_bytes is None:
            raise AdapterError("NOT_FOUND", "signed bytes were not persisted")
        broadcast = self.lab.broadcast_exact(reserved.operation_id, signed_bytes, fence)
        if broadcast.certainty is Certainty.UNKNOWN:
            return broadcast
        self.broadcasts += 1
        return broadcast


class AdapterHarness:
    """Fault-injecting wrapper around LabPartnerAdapters."""

    def __init__(self, **kwargs):
        self.lab = LabPartnerAdapters(**kwargs)
        self.executor = LabExecutor(self.lab)

    @property
    def automatic_spend_atoms(self) -> int:
        return self.lab.automatic_spend_atoms

    def inject_sign_timeout(self) -> None:
        self.lab.faults.sign_timeout = True

    def inject_broadcast_timeout(self) -> None:
        self.lab.faults.broadcast_timeout = True

    def inject_reserve_timeout(self) -> None:
        self.lab.faults.reserve_timeout = True

    def inject_quote_timeout(self) -> None:
        self.lab.faults.quote_timeout = True

    def inject_observe_timeout(self) -> None:
        self.lab.faults.observe_timeout = True

    def assert_unknown_not_failure(self, outcome: EffectOutcome) -> None:
        if outcome.certainty is not Certainty.UNKNOWN:
            raise AssertionError(f"expected UNKNOWN, got {outcome.certainty}")
        if self.lab.automatic_spend_atoms != 0:
            raise AssertionError("automatic_spend_atoms left lab zero")

    def refuse_unsafe_followups(self, operation_id: str) -> None:
        """Prove the three forbidden follow-ups while UNKNOWN."""
        try:
            self.lab.auto_submit_finance(operation_id)
        except AdapterError as exc:
            if exc.code not in {"UNKNOWN_NOT_SAFE_FAILURE", "AUTO_SUBMIT_FORBIDDEN"}:
                raise
        else:
            raise AssertionError("auto-submit must refuse")
        try:
            self.lab.construct_replacement_spend(operation_id, b"replacement-spend")
        except AdapterError as exc:
            if exc.code != "REPLACEMENT_SPEND_FORBIDDEN":
                raise
        else:
            raise AssertionError("replacement spend must refuse")
        try:
            self.lab.failover_venue(operation_id, "lab-venue-b")
        except AdapterError as exc:
            if exc.code != "VENUE_FAILOVER_FORBIDDEN":
                raise
        else:
            raise AssertionError("venue failover must refuse")


__all__ = (
    "AdapterHarness",
    "AUTOMATIC_SPEND_ATOMS",
    "AdapterError",
    "Caller",
    "Certainty",
    "DisabledProductionSigner",
    "EVIDENCE_SIMULATION_ONLY",
    "EffectOutcome",
    "EvmGenericCustody",
    "LabExecutor",
    "LabPartnerAdapters",
    "NativeFamily",
    "lab_caller",
    "reject_webhook_url",
)
