# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Simulator failure semantics used by partner adapters: UNKNOWN is not safe failure."""
from __future__ import annotations

import json
import sys
import types
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_PKG = "hcp_reference"
if _PKG not in sys.modules:
    _pkg = types.ModuleType(_PKG)
    _pkg.__path__ = [str(_HERE)]
    _pkg.__file__ = str(_HERE / "__init__.py")
    _pkg.__package__ = _PKG
    sys.modules[_PKG] = _pkg

from hcp_reference.adapter_contracts import DisabledProductionSigner  # noqa: E402
from hcp_reference.contracts import ContractError  # noqa: E402
from hcp_reference.simulator import Simulation  # noqa: E402

ROOT = Path(__file__).resolve().parents[3]
EXAMPLES = ROOT / "src" / "modelnet" / "hcp" / "examples"
NOW = 1790000000100


def _policy(**overrides):
    policy = json.loads((EXAMPLES / "HostedAccountPolicy.json").read_text())
    policy.update(overrides)
    return policy


def _intent(n: int = 1):
    body = json.loads((EXAMPLES / "FinanceIntent.unsigned.json").read_text())["body"]
    body["client_operation_id"] = f"op-sim-{n}"
    body["intent_id"] = f"intent-sim-{n}"
    return body


def _reserved(sim: Simulation, n: int = 1):
    intent = sim.create(_intent(n))
    sim.authorize(intent, intent.digest, NOW)
    sim.reserve(intent, NOW)
    return intent


class SimulatorUnknownTests(unittest.TestCase):
    def test_simulation_only_and_zero_native(self):
        sim = Simulation(10000, _policy())
        summary = sim.summary()
        self.assertEqual(summary["evidence"], "SIMULATION_ONLY")
        self.assertEqual(summary["native_transactions"], 0)
        self.assertEqual(summary["runtime_executions"], 0)

    def test_lost_broadcast_stays_unknown_same_bytes(self):
        sim = Simulation(10000, _policy())
        intent = _reserved(sim)
        ref = sim.simulate_sign(intent)
        first = sim.simulate_dispatch(intent, response_lost=True)
        self.assertEqual(intent.state, "BROADCAST_UNKNOWN")
        self.assertEqual(first, ref)
        retry = sim.simulate_dispatch(intent)
        self.assertEqual(retry, ref)
        self.assertEqual(intent.dispatch_attempts, 2)
        self.assertEqual(sim.summary()["held"], 1050)
        self.assertEqual(sim.summary()["native_transactions"], 0)

    def test_cannot_cancel_after_sign(self):
        sim = Simulation(10000, _policy())
        intent = _reserved(sim)
        sim.simulate_sign(intent)
        with self.assertRaises(ContractError):
            sim.cancel(intent)
        self.assertEqual(sim.summary()["held"], 1050)

    def test_confirm_from_unknown(self):
        sim = Simulation(10000, _policy())
        intent = _reserved(sim)
        sim.simulate_sign(intent)
        sim.simulate_dispatch(intent, response_lost=True)
        sim.simulate_confirm(intent, 20)
        self.assertEqual(intent.state, "CONFIRMED")
        before = sim.summary()
        sim.simulate_confirm(intent, 20)
        self.assertEqual(sim.summary(), before)

    def test_duplicate_reserve_idempotent(self):
        sim = Simulation(10000, _policy())
        intent = _reserved(sim)
        sim.reserve(intent, NOW)
        self.assertEqual(sim.summary()["held"], 1050)

    def test_disabled_signer_still_unsupported(self):
        with self.assertRaises(RuntimeError) as ctx:
            DisabledProductionSigner().sign_exact()
        self.assertIn("CUSTODY_UNSUPPORTED", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
