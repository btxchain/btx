#!/usr/bin/env python3
"""Focused schema tests for the ENC-DR-LT offline gate."""

from __future__ import annotations

import importlib.util
import math
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("lt-gate.py")
SPEC = importlib.util.spec_from_file_location("lt_gate", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
lt_gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(lt_gate)


def report(
    name: str,
    nps: object,
    *,
    backend: str = "cuda",
    backend_used_device: object = True,
    device_rate_valid: object = True,
    silicon_rate_valid: object = True,
    execution_path: object = "device-resident-qstar-batched",
    assisted_exact: object = True,
    qstar_is_consensus: object = True,
    qstar_device_batched: object = True,
    device_w_generation: object = True,
    device_digest: object = True,
    per_nonce_sync_absent: object = True,
    rate_provenance: object = "device-resident-qstar-batched",
    native_path_eligible: object = True,
    tensor_share_pct: object = 70.0,
    device_tensor_share_pct: object = 70.0,
    device_tensor_timing_valid: object = True,
    device_tensor_counters_valid: object = True,
    device_tensor_timing_domain: object = "device-kernel-timing-and-counters",
    tensor_util_pct: object = 60.0,
    n: object = 4096,
    window: object = 128,
    rounds: object = 3,
    measurement_mode: object = "phase-a-digest",
    source_revision: object = "1ca87fb",
    host_cpu_model: object | None = None,
    host_cpu_provenance_complete: object = True,
    host_independence_verified: object = True,
    device_rate_timing_valid: object = True,
    device_rate_timing_domain: object = "device-events-resident-qstar",
    device_execution_certified: object = True,
    device_rate_certified: object = True,
    throughput_scheduler: object = "ringed-device-steady-state",
    throughput_campaign_windows_requested: object = 8,
    throughput_ring_depth: object = 8,
    throughput_chat_staging_slots: object = 4,
    throughput_chat_staging_chunks: object = 2,
    throughput_cross_window_overlap: object = True,
    throughput_saturation_verified: object = True,
    peak_status_measured: object = True,
    peak_capable: object = True,
    peak_ready: object = True,
    resident_native_mx_wired: object = True,
    native_mxfp4_qualified: object = True,
    native_fp8_qualified: object = False,
    v3_hashrate: object = 0.0,
    asert: object = "n/a (pass --v3-hashrate)",
) -> dict:
    return {
        "_file": name,
        "tool": "matmul-v4-report",
        "schema_version": 3,
        "profile": "bmx4c-lt",
        "host": name.removesuffix(".json"),
        "host_cpu": {
            "architecture": "x86_64",
            "model": host_cpu_model or ("test CPU for " + name),
            "logical_cpus": 32,
            "cpu_affinity_list": "0-31",
            "memory_node_affinity_list": "0",
        },
        "host_cpu_provenance_complete": host_cpu_provenance_complete,
        "backend": backend,
        "n": n,
        "window": window,
        "rounds": rounds,
        "measurement_mode": measurement_mode,
        "source_revision": source_revision,
        "native_path_eligible": native_path_eligible,
        "device_execution_certified": device_execution_certified,
        "device_rate_certified": device_rate_certified,
        "throughput_scheduler": throughput_scheduler,
        "throughput_campaign_windows_requested": throughput_campaign_windows_requested,
        "throughput_ring_depth": throughput_ring_depth,
        "throughput_chat_staging_slots": throughput_chat_staging_slots,
        "throughput_chat_staging_chunks": throughput_chat_staging_chunks,
        "throughput_cross_window_overlap": throughput_cross_window_overlap,
        "throughput_saturation_verified": throughput_saturation_verified,
        "device_rate_timing_valid": device_rate_timing_valid,
        "device_rate_timing_domain": device_rate_timing_domain,
        "host_independence_verified": host_independence_verified,
        "device_tensor_timing_valid": device_tensor_timing_valid,
        "device_tensor_counters_valid": device_tensor_counters_valid,
        "device_tensor_timing_domain": device_tensor_timing_domain,
        "device_tensor_share_pct": device_tensor_share_pct,
        "backend_used_device": backend_used_device,
        "device_rate_valid": device_rate_valid,
        "silicon_rate_valid": silicon_rate_valid,
        "execution_path": execution_path,
        "bit_exact": True,
        "stages": {
            "bit_exact": True,
            "cpu_reference_tensor_share_pct": tensor_share_pct,
            "tensor_share_pct": tensor_share_pct,
            "device_tensor_share_pct": device_tensor_share_pct,
            "tensor_util_pct": tensor_util_pct,
        },
        "cpu_reference_tensor_share_pct": tensor_share_pct,
        "tensor_share_pct": None,
        "tensor_util_pct": tensor_util_pct,
        "device_nonce_per_s": nps,
        "cpu_reference_nonce_per_s": 999999.0,
        "v3_hashrate": v3_hashrate,
        "asert_rescale_num_den_suggestion": asert,
        "lt": {
            "device_native_kernel_wired": native_path_eligible,
            "device_assisted_path_exact": assisted_exact,
            "qstar_is_consensus": qstar_is_consensus,
            "qstar_device_batched": qstar_device_batched,
            "device_w_generation": device_w_generation,
            "device_digest": device_digest,
            "per_nonce_sync_absent": per_nonce_sync_absent,
            "rate_provenance": rate_provenance,
            "peak_status_measured": peak_status_measured,
            "peak_capable": peak_capable,
            "peak_ready": peak_ready,
            "resident_native_mx_wired": resident_native_mx_wired,
            "native_mxfp4_qualified": native_mxfp4_qualified,
            "native_fp8_qualified": native_fp8_qualified,
        },
    }


LABELS = {
    "b200.json": ("nvidia", "datacenter", "B200"),
    "5090.json": ("nvidia", "consumer", "RTX5090"),
}


class LtGateSchemaTest(unittest.TestCase):
    def evaluate_pair(self, dc: dict, consumer: dict):
        return lt_gate.evaluate([dc, consumer], LABELS, {}, False)

    def test_positive_resident_batched_rate_and_device_counters_drive_g1_g2(self):
        go, gates, rows, reasons, notes, summary = self.evaluate_pair(
            report("b200.json", 400.0), report("5090.json", 100.0)
        )

        self.assertFalse(go)  # G3-G8 remain deliberately fail-closed.
        self.assertTrue(gates["G1_tensor_majority"])
        self.assertTrue(gates["G2_b200_5090_ratio"])
        self.assertEqual([row["nps"] for row in rows], [400.0, 100.0])
        self.assertTrue(all(row["device_measured"] for row in rows))
        self.assertTrue(all(row["native_path_eligible"] for row in rows))
        self.assertEqual(summary["g2_evidence"]["ratio"], 4.0)
        self.assertEqual(
            summary["g2_evidence"]["comparison_config"],
            {
                "n": 4096,
                "window": 128,
                "rounds": 3,
                "measurement_mode": "phase-a-digest",
                "source_revision": "1ca87fb",
                "throughput_scheduler": "ringed-device-steady-state",
                "throughput_campaign_windows_requested": 8,
                "throughput_cross_window_overlap": True,
            },
        )
        self.assertFalse(any("G2 B200/5090 ratio" in reason for reason in reasons))

    def test_g2_requires_saturated_scheduler_provenance(self):
        for override in (
            {"throughput_scheduler": None},
            {"throughput_ring_depth": None},
            {"throughput_chat_staging_slots": None},
            {"throughput_chat_staging_chunks": None},
            {"throughput_saturation_verified": False},
        ):
            dc = report("b200.json", 400.0, **override)
            consumer = report("5090.json", 100.0)
            _, gates, rows, reasons, _, _ = self.evaluate_pair(dc, consumer)
            self.assertFalse(gates["G2_b200_5090_ratio"])
            self.assertFalse(rows[0]["device_measured"])
            self.assertTrue(any("G2" in reason and "UNVERIFIED" in reason for reason in reasons))

    def test_g2_matches_scheduler_policy_not_device_capacity(self):
        dc = report(
            "b200.json", 400.0,
            throughput_ring_depth=64,
            throughput_chat_staging_slots=64,
            throughput_chat_staging_chunks=2,
        )
        consumer = report(
            "5090.json", 100.0,
            throughput_ring_depth=8,
            throughput_chat_staging_slots=8,
            throughput_chat_staging_chunks=16,
        )
        _, gates, _, _, _, summary = self.evaluate_pair(dc, consumer)
        self.assertTrue(gates["G2_b200_5090_ratio"])
        self.assertEqual(summary["g2_evidence"]["datacenter_chat_staging_slots"], 64)
        self.assertEqual(summary["g2_evidence"]["consumer_chat_staging_slots"], 8)

        consumer["throughput_scheduler"] = "sequential-synchronous-qstar"
        _, gates, _, reasons, _, _ = self.evaluate_pair(dc, consumer)
        self.assertFalse(gates["G2_b200_5090_ratio"])
        self.assertTrue(any("no comparable" in reason for reason in reasons))

    def test_g4_requires_resident_qualified_native_mx(self):
        labels = {"mi350.json": ("amd", "datacenter", "MI350")}
        candidate = report("mi350.json", 200.0, backend="hip")
        _, gates, _, reasons, _, _ = lt_gate.evaluate(
            [candidate], labels, {}, False
        )
        self.assertTrue(gates["G4_mi350_exactness"])
        self.assertFalse(any("G4 MI350/OCP MX FAIL" in reason for reason in reasons))

        for field in (
            "peak_status_measured",
            "peak_capable",
            "peak_ready",
            "resident_native_mx_wired",
            "native_mxfp4_qualified",
        ):
            with self.subTest(field=field):
                deficient = report("mi350.json", 200.0, backend="hip")
                deficient["lt"][field] = False
                _, deficient_gates, _, deficient_reasons, _, _ = lt_gate.evaluate(
                    [deficient], labels, {}, False
                )
                self.assertFalse(deficient_gates["G4_mi350_exactness"])
                self.assertTrue(any(
                    "G4 MI350/OCP MX FAIL" in reason
                    for reason in deficient_reasons
                ))

    def test_g2_allows_different_hosts_when_device_timing_is_host_independent(self):
        dc = report(
            "b200.json", 400.0,
            host_cpu_model="NVIDIA Grace",
        )
        consumer = report(
            "5090.json", 100.0,
            host_cpu_model="AMD EPYC 7742",
        )
        dc["host_cpu"]["cpu_affinity_list"] = "0-71"
        dc["host_cpu"]["logical_cpus"] = 72
        consumer["host_cpu"]["cpu_affinity_list"] = "128-255"
        consumer["host_cpu"]["logical_cpus"] = 256

        _, gates, _, _, _, summary = self.evaluate_pair(dc, consumer)

        self.assertTrue(gates["G2_b200_5090_ratio"])
        self.assertEqual(summary["g2_evidence"]["datacenter_host_cpu"]["model"],
                         "NVIDIA Grace")
        self.assertEqual(summary["g2_evidence"]["consumer_host_cpu"]["model"],
                         "AMD EPYC 7742")

    def test_g2_rejects_resident_host_wall_rate_without_host_independence(self):
        for field, value in (
            ("host_independence_verified", False),
            ("device_rate_timing_valid", False),
            ("device_rate_timing_domain", "host-wall-resident-batch"),
            ("native_path_eligible", False),
            ("device_execution_certified", False),
            ("device_rate_certified", False),
        ):
            with self.subTest(field=field):
                dc = report("b200.json", 400.0, **{field: value})
                dc["resident_batch_wall_nonce_per_s"] = 400.0
                _, gates, rows, reasons, _, _ = self.evaluate_pair(
                    dc, report("5090.json", 100.0)
                )
                self.assertFalse(gates["G2_b200_5090_ratio"])
                self.assertIsNone(rows[0]["nps"])
                self.assertEqual(rows[0]["host_orchestrated_nps"], 400.0)
                self.assertTrue(any("UNVERIFIED" in reason for reason in reasons))

    def test_g2_rejects_missing_host_cpu_provenance(self):
        for mutation in (
            lambda candidate: candidate.pop("host_cpu"),
            lambda candidate: candidate["host_cpu"].update({"model": "unknown"}),
            lambda candidate: candidate["host_cpu"].update({"cpu_affinity_list": "unavailable"}),
            lambda candidate: candidate.update({"host_cpu_provenance_complete": False}),
        ):
            with self.subTest(mutation=mutation):
                dc = report("b200.json", 400.0)
                mutation(dc)
                _, gates, rows, _, _, _ = self.evaluate_pair(
                    dc, report("5090.json", 100.0)
                )
                self.assertFalse(gates["G2_b200_5090_ratio"])
                self.assertFalse(rows[0]["host_cpu_provenance_complete"])
                self.assertIsNone(rows[0]["nps"])

    def test_g2_rejects_incomparable_workload_mode_or_revision(self):
        mismatches = {
            "n": 64,
            "window": 256,
            "rounds": 5,
            "measurement_mode": "phase-b-seal",
            "source_revision": "new-tip",
        }
        for field, value in mismatches.items():
            with self.subTest(field=field):
                consumer = report("5090.json", 100.0, **{field: value})
                _, gates, _, reasons, _, summary = self.evaluate_pair(
                    report("b200.json", 400.0), consumer
                )
                self.assertFalse(gates["G2_b200_5090_ratio"])
                self.assertIsNone(summary["g2_evidence"]["ratio"])
                self.assertTrue(any("no comparable" in reason for reason in reasons))

    def test_g2_rejects_missing_or_invalid_comparison_identity(self):
        invalid = (None, "", 0, True)
        for field in ("n", "window", "rounds", "measurement_mode", "source_revision"):
            for value in invalid:
                with self.subTest(field=field, value=value):
                    candidate = report("b200.json", 400.0)
                    candidate[field] = value
                    self.assertIsNone(lt_gate.g2_comparison_config(candidate))
                    _, gates, _, reasons, _, _ = self.evaluate_pair(
                        candidate, report("5090.json", 100.0)
                    )
                    self.assertFalse(gates["G2_b200_5090_ratio"])
                    self.assertTrue(any("no comparable" in reason for reason in reasons))

        dirty = report("b200.json", 400.0, source_revision="1ca87fb-dirty")
        self.assertIsNone(lt_gate.g2_comparison_config(dirty))
        _, gates, _, reasons, _, _ = self.evaluate_pair(
            dirty, report("5090.json", 100.0)
        )
        self.assertFalse(gates["G2_b200_5090_ratio"])
        self.assertTrue(any("no comparable" in reason for reason in reasons))

    def test_g2_ignores_faster_but_incompatible_report(self):
        dc_fast_wrong_shape = report("b200-fast.json", 1000.0, n=64, window=64)
        dc_matched = report("b200.json", 400.0)
        consumer = report("5090.json", 100.0)
        labels = {
            **LABELS,
            "b200-fast.json": ("nvidia", "datacenter", "B200"),
        }

        _, gates, _, _, _, summary = lt_gate.evaluate(
            [dc_fast_wrong_shape, dc_matched, consumer], labels, {}, False
        )

        self.assertTrue(gates["G2_b200_5090_ratio"])
        self.assertEqual(summary["g2_evidence"]["datacenter_file"], "b200.json")
        self.assertEqual(summary["g2_evidence"]["consumer_file"], "5090.json")
        self.assertEqual(summary["g2_evidence"]["ratio"], 4.0)

    def test_g2_ignores_other_datacenter_and_consumer_models(self):
        reports = [
            report("b200.json", 400.0),
            report("5090.json", 100.0),
            report("h200.json", 2000.0),
            report("5060.json", 2000.0),
        ]
        labels = {
            **LABELS,
            "h200.json": ("nvidia", "datacenter", "H200"),
            "5060.json": ("nvidia", "consumer", "RTX 5060 Ti"),
        }

        _, gates, _, _, _, summary = lt_gate.evaluate(reports, labels, {}, False)

        self.assertTrue(gates["G2_b200_5090_ratio"])
        self.assertEqual(summary["g2_evidence"]["datacenter_file"], "b200.json")
        self.assertEqual(summary["g2_evidence"]["consumer_file"], "5090.json")

    def test_g1_rejects_non_normative_datacenter_consumer_without_ack(self):
        """Assessment #7: G1 must not accept arbitrary datacenter/consumer parts."""
        labels = {
            "h200.json": ("nvidia", "datacenter", "H200"),
            "5060.json": ("nvidia", "consumer", "RTX 5060 Ti"),
        }
        _, gates, _, reasons, notes, summary = lt_gate.evaluate(
            [report("h200.json", 400.0), report("5060.json", 100.0)],
            labels,
            {},
            False,
        )
        self.assertFalse(gates["G1_tensor_majority"])
        self.assertFalse(summary.get("ack_non_normative_gpu"))
        self.assertTrue(any("B200" in r for r in reasons))
        self.assertTrue(any("5090" in r for r in reasons))
        self.assertFalse(any("ACK-NON-NORMATIVE-GPU" in n for n in notes))

        _, gates_ack, _, _, notes_ack, summary_ack = lt_gate.evaluate(
            [report("h200.json", 400.0), report("5060.json", 100.0)],
            labels,
            {},
            False,
            ack_non_normative_gpu=True,
        )
        self.assertTrue(gates_ack["G1_tensor_majority"])
        self.assertTrue(summary_ack.get("ack_non_normative_gpu"))
        self.assertTrue(any("ACK-NON-NORMATIVE-GPU" in n for n in notes_ack))

    def test_g4_rejects_non_mi350_amd_without_ack(self):
        labels = {"mi300.json": ("amd", "datacenter", "MI300X")}
        candidate = report("mi300.json", 200.0, backend="hip")
        _, gates, _, reasons, _, _ = lt_gate.evaluate(
            [candidate], labels, {}, False
        )
        self.assertFalse(gates["G4_mi350_exactness"])
        self.assertTrue(any("MI350" in r for r in reasons))

        _, gates_ack, _, _, notes_ack, _ = lt_gate.evaluate(
            [candidate], labels, {}, False, ack_non_normative_gpu=True
        )
        self.assertTrue(gates_ack["G4_mi350_exactness"])
        self.assertTrue(any("ACK-NON-NORMATIVE-GPU" in n for n in notes_ack))

    def test_g2_rejects_multiple_compatible_campaigns_without_cherry_picking(self):
        reports = [
            report("b200.json", 400.0),
            report("5090.json", 100.0),
            report("b200-old.json", 600.0, source_revision="old-tip"),
            report("5090-old.json", 100.0, source_revision="old-tip"),
        ]
        labels = {
            **LABELS,
            "b200-old.json": ("nvidia", "datacenter", "B200"),
            "5090-old.json": ("nvidia", "consumer", "RTX5090"),
        }

        _, gates, _, reasons, _, summary = lt_gate.evaluate(reports, labels, {}, False)

        self.assertFalse(gates["G2_b200_5090_ratio"])
        self.assertIsNone(summary["g2_evidence"]["ratio"])
        self.assertTrue(any("multiple comparable" in reason for reason in reasons))

    def test_g3_requires_costed_reports_from_same_production_campaign(self):
        costs = {"B200": 1.0, "RTX5090": 1.0}
        dc = report("b200.json", 400.0)
        consumer = report("5090.json", 100.0)

        _, gates, _, _, _, _ = lt_gate.evaluate([dc, consumer], LABELS, costs, False)
        self.assertTrue(gates["G3_nonce_per_dollar"])

        consumer["source_revision"] = "other-tip"
        _, gates, _, reasons, _, _ = lt_gate.evaluate(
            [dc, consumer], LABELS, costs, False
        )
        self.assertFalse(gates["G3_nonce_per_dollar"])
        self.assertTrue(
            any("G3" in reason and "no exact workload/build-matched" in reason
                for reason in reasons)
        )

    def test_g3_ignores_cheaper_but_incompatible_report(self):
        dc = report("b200.json", 400.0)
        consumer = report("5090.json", 100.0)
        incompatible_consumer = report(
            "5090-small.json", 1000.0, n=64, window=64, source_revision="old-tip"
        )
        labels = {
            **LABELS,
            "5090-small.json": ("nvidia", "consumer", "RTX 5090 small"),
        }
        costs = {
            "b200.json": 4.0,
            "5090.json": 1.0,
            "5090-small.json": 0.01,
        }

        _, gates, _, reasons, _, _ = lt_gate.evaluate(
            [dc, consumer, incompatible_consumer], labels, costs, False
        )

        self.assertTrue(gates["G3_nonce_per_dollar"])
        self.assertFalse(any("G3 REWARD INVERSION" in reason for reason in reasons))

    def test_g3_is_unverified_without_a_comparable_campaign(self):
        dc = report("b200.json", 400.0)
        consumer = report("5090.json", 100.0, n=64)
        _, gates, _, reasons, _, _ = lt_gate.evaluate(
            [dc, consumer], LABELS, {"b200.json": 1.0, "5090.json": 1.0}, False
        )

        self.assertFalse(gates["G3_nonce_per_dollar"])
        self.assertTrue(
            any("G3" in reason and "no exact workload/build-matched" in reason for reason in reasons)
        )

    def test_g2_silicon_rate_does_not_substitute_for_g1_native_counters(self):
        dc = report(
            "b200.json", 400.0, native_path_eligible=True,
            device_tensor_timing_valid=False, device_tensor_counters_valid=False,
            device_tensor_timing_domain="cpu-reference", device_tensor_share_pct=None,
            tensor_share_pct=97.2,
        )
        consumer = report(
            "5090.json", 100.0, native_path_eligible=True,
            device_tensor_timing_valid=False, device_tensor_counters_valid=False,
            device_tensor_timing_domain="cpu-reference", device_tensor_share_pct=None,
            tensor_share_pct=97.2,
        )

        _, gates, rows, reasons, _, _ = self.evaluate_pair(dc, consumer)

        self.assertFalse(gates["G1_tensor_majority"])
        self.assertTrue(gates["G2_b200_5090_ratio"])
        self.assertTrue(all(r["cpu_reference_tensor_share_pct"] == 97.2 for r in rows))
        self.assertTrue(all(r["device_tensor_share_pct"] is None for r in rows))
        self.assertTrue(any("cpu_reference_tensor_share_pct=97.2% does not count" in reason
                            for reason in reasons))

    def test_null_and_invalid_device_rates_fail_closed(self):
        invalid = [None, 0, -1, math.nan, math.inf, -math.inf, "100"]
        for value in invalid:
            with self.subTest(value=value):
                candidate = report("b200.json", value)
                self.assertFalse(lt_gate.device_measured(candidate))
                self.assertIsNone(lt_gate.device_nps(candidate))

        _, gates, rows, reasons, _, summary = self.evaluate_pair(
            report("b200.json", None), report("5090.json", 100.0)
        )
        self.assertFalse(gates["G2_b200_5090_ratio"])
        self.assertIsNone(rows[0]["nps"])
        self.assertIsNone(summary["g2_evidence"]["ratio"])
        self.assertTrue(any("UNVERIFIED" in reason and "G2" in reason for reason in reasons))

    def test_rate_requires_complete_exact_device_assisted_provenance(self):
        self.assertFalse(
            lt_gate.device_measured(report("b200.json", 400.0, backend_used_device=False))
        )
        self.assertFalse(
            lt_gate.device_measured(report("b200.json", 400.0, device_rate_valid=False))
        )
        self.assertFalse(
            lt_gate.device_measured(report("b200.json", 400.0, silicon_rate_valid=False))
        )
        self.assertFalse(
            lt_gate.device_measured(report("b200.json", 400.0, execution_path="device-assisted-end-to-end"))
        )
        self.assertFalse(
            lt_gate.device_measured(report("b200.json", 400.0, assisted_exact=False))
        )
        self.assertFalse(lt_gate.device_measured(report("b200.json", 400.0, backend="cpu")))
        wrong_type = report("b200.json", 400.0)
        wrong_type["backend_used_device"] = 1
        self.assertFalse(lt_gate.device_measured(wrong_type))

        for top_level in ("backend_used_device", "device_rate_valid", "silicon_rate_valid", "execution_path"):
            with self.subTest(missing=top_level):
                missing = report("b200.json", 400.0)
                del missing[top_level]
                self.assertFalse(lt_gate.device_measured(missing))
        missing_nested = report("b200.json", 400.0)
        del missing_nested["lt"]["device_assisted_path_exact"]
        self.assertFalse(lt_gate.device_measured(missing_nested))

        for field in (
            "qstar_is_consensus",
            "qstar_device_batched",
            "device_w_generation",
            "device_digest",
            "per_nonce_sync_absent",
        ):
            with self.subTest(false_provenance=field):
                candidate = report("b200.json", 400.0)
                candidate["lt"][field] = False
                self.assertFalse(lt_gate.device_measured(candidate))
            with self.subTest(missing_provenance=field):
                candidate = report("b200.json", 400.0)
                del candidate["lt"][field]
                self.assertFalse(lt_gate.device_measured(candidate))

        wrong_provenance = report("b200.json", 400.0)
        wrong_provenance["lt"]["rate_provenance"] = "cuda/hip-device-assisted-status-ok"
        self.assertFalse(lt_gate.device_measured(wrong_provenance))

    def test_host_orchestrated_1ca87fb_rates_are_diagnostic_only(self):
        dc = report(
            "b200.json",
            None,
            device_rate_valid=False,
            silicon_rate_valid=False,
            execution_path="device-assisted-per-nonce-host-orchestrated",
            qstar_device_batched=False,
            device_w_generation=False,
            device_digest=False,
            per_nonce_sync_absent=False,
            rate_provenance="host-orchestrated-single-nonce-diagnostic",
            native_path_eligible=False,
            device_tensor_timing_valid=False,
            device_tensor_counters_valid=False,
            device_tensor_timing_domain="cpu-reference",
            device_tensor_share_pct=None,
        )
        dc["host_orchestrated_nonce_per_s"] = 118.92
        dc["asert_rescale_num_den_suggestion"] = "100/1"
        consumer = report(
            "5090.json",
            None,
            device_rate_valid=False,
            silicon_rate_valid=False,
            execution_path="device-assisted-per-nonce-host-orchestrated",
            qstar_device_batched=False,
            device_w_generation=False,
            device_digest=False,
            per_nonce_sync_absent=False,
            rate_provenance="host-orchestrated-single-nonce-diagnostic",
            native_path_eligible=False,
            device_tensor_timing_valid=False,
            device_tensor_counters_valid=False,
            device_tensor_timing_domain="cpu-reference",
            device_tensor_share_pct=None,
        )
        consumer["host_orchestrated_nonce_per_s"] = 77.08

        _, gates, rows, reasons, notes, summary = lt_gate.evaluate(
            [dc, consumer], LABELS, {"B200": 7.0, "RTX5090": 0.5}, False
        )

        self.assertFalse(gates["G1_tensor_majority"])
        self.assertFalse(gates["G2_b200_5090_ratio"])
        self.assertFalse(gates["G3_nonce_per_dollar"])
        self.assertEqual([r["host_orchestrated_nps"] for r in rows], [118.92, 77.08])
        self.assertEqual([r["nps"] for r in rows], [None, None])
        self.assertIsNone(summary["g2_evidence"]["ratio"])
        self.assertTrue(any("G2" in reason and "UNVERIFIED" in reason for reason in reasons))
        self.assertTrue(any("G3" in reason and "UNVERIFIED" in reason for reason in reasons))
        self.assertTrue(any("diagnostic only" in note for note in notes))
        self.assertTrue(any("exclude it from calibration" in note for note in notes))

    def test_telemetry_only_report_is_diagnostic_not_consensus_failure(self):
        telemetry = report(
            "telemetry.json",
            None,
            device_rate_valid=False,
            silicon_rate_valid=False,
            execution_path="telemetry-only-device-resident-qstar-batched",
            assisted_exact=False,
            rate_provenance="telemetry-only-device-resident-qstar-batched",
            native_path_eligible=False,
            device_tensor_timing_valid=False,
            device_tensor_counters_valid=False,
            device_tensor_timing_domain="not-measured-telemetry-only",
            device_tensor_share_pct=None,
            measurement_mode="telemetry-only-device-resident-qstar",
        )
        telemetry["telemetry_only"] = True
        telemetry["bit_exact"] = None
        telemetry["stages"] = None
        telemetry["telemetry_device_nonce_per_s"] = 3.5

        labels = {
            **LABELS,
            "telemetry.json": ("nvidia", "datacenter", "B200 telemetry"),
        }
        _, gates, rows, reasons, notes, summary = lt_gate.evaluate(
            [report("b200.json", 400.0), report("5090.json", 100.0), telemetry],
            labels,
            {},
            False,
        )

        self.assertTrue(gates["G1_tensor_majority"])
        self.assertTrue(gates["G2_b200_5090_ratio"])
        self.assertEqual(summary["g2_evidence"]["ratio"], 4.0)
        self.assertEqual(len(rows), 3)
        self.assertFalse(any("telemetry.json" in reason for reason in reasons))
        self.assertTrue(any("telemetry-only/non-certifying" in note for note in notes))

    def test_telemetry_measurement_mode_overrides_contradictory_rate_claim(self):
        telemetry = report(
            "telemetry-contradictory.json",
            1000.0,
            device_rate_valid=True,
            silicon_rate_valid=True,
            measurement_mode="telemetry-only-device-resident-qstar",
        )
        telemetry["telemetry_only"] = False
        labels = {
            **LABELS,
            "telemetry-contradictory.json": ("nvidia", "datacenter", "B200 telemetry"),
        }

        _, gates, _, reasons, notes, summary = lt_gate.evaluate(
            [report("b200.json", 400.0), report("5090.json", 100.0), telemetry],
            labels,
            {},
            False,
        )

        self.assertTrue(gates["G2_b200_5090_ratio"])
        self.assertEqual(summary["g2_evidence"]["ratio"], 4.0)
        self.assertFalse(any("telemetry-contradictory.json" in reason for reason in reasons))
        self.assertTrue(any("telemetry-only/non-certifying" in note for note in notes))

    def test_tensor_util_is_diagnostic_not_g1_input(self):
        dc = report("b200.json", 400.0, tensor_util_pct="unknown")
        dc["tensor_util_pct"] = None
        consumer = report("5090.json", 100.0, tensor_util_pct=None)
        consumer["stages"]["tensor_util_pct"] = 47.5

        _, gates, rows, _, _, _ = self.evaluate_pair(dc, consumer)
        self.assertTrue(gates["G1_tensor_majority"])
        self.assertIsNone(rows[0]["tensor_util_pct"])
        self.assertEqual(rows[1]["tensor_util_pct"], 47.5)

    def test_device_tensor_share_must_be_strict_majority_and_counter_backed(self):
        for kwargs in (
            {"device_tensor_share_pct": 50.0},
            {"device_tensor_timing_valid": False},
            {"device_tensor_counters_valid": False},
            {"device_tensor_timing_domain": "cpu-reference"},
            {"native_path_eligible": False},
        ):
            with self.subTest(kwargs=kwargs):
                dc = report("b200.json", 400.0, **kwargs)
                _, gates, _, reasons, _, _ = self.evaluate_pair(
                    dc, report("5090.json", 100.0)
                )
                self.assertFalse(gates["G1_tensor_majority"])
                self.assertTrue(any("G1 native tensor-majority" in reason for reason in reasons))

    def test_commit_only_s5_cannot_pass_phase_b_review(self):
        dc = report("b200.json", 400.0)
        consumer = report("5090.json", 100.0)
        for candidate in (dc, consumer):
            candidate["stages"]["s5_qstar_seal_ms"] = 1.0
            # Even a forged/legacy optimistic field cannot make the offline
            # aggregator treat a commit-only clock as consensus-equivalent.
            candidate["phase_b_seal_rate_valid"] = True
            candidate["phase_b_consensus_equivalent"] = True

        _, gates, _, reasons, _, _ = self.evaluate_pair(dc, consumer)

        self.assertFalse(gates["G8_seal_as_pow_review"])
        self.assertTrue(any("G8 Phase B" in reason and "UNVERIFIED" in reason
                            for reason in reasons))

    def test_asert_suggestion_is_checked_against_measured_ratio(self):
        dc = report("b200.json", 400.0, v3_hashrate=1200.0, asert="3/1")
        consumer = report("5090.json", 100.0, v3_hashrate=1200.0, asert="12/1")

        _, gates, rows, _, notes, summary = self.evaluate_pair(dc, consumer)
        self.assertTrue(gates["G2_b200_5090_ratio"])
        self.assertEqual(rows[0]["asert_expected"], "3/1")
        self.assertTrue(rows[0]["asert_consistent"])
        self.assertEqual(rows[1]["asert_expected"], "12/1")
        self.assertTrue(rows[1]["asert_consistent"])
        self.assertFalse(notes)
        self.assertEqual(len(summary["asert_calibration"]), 2)

        bad = report("b200.json", 100.0, v3_hashrate=1200.0, asert="24/2")
        self.assertIsNone(lt_gate.asert_suggestion(bad))
        self.assertEqual(lt_gate.expected_asert_suggestion(bad), "12/1")


if __name__ == "__main__":
    unittest.main()
