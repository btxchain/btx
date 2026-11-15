# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see COPYING.
"""Negative-path and byte-contract tests, never hardware qualification receipts."""

import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import checkpoint_bridge
import collect_runtime
import evidence
import native_model
import native_node
import offline_exec
import offline_image
import wan_peers


class CheckpointBridgeTests(unittest.TestCase):
    def test_dense_witness_consumes_actual_f32_bytes(self):
        weights = struct.pack("<6f", 1, 2, 3, 4, 5, 6)
        result = checkpoint_bridge.linear_witness(weights, [2, 3], struct.pack("<2f", .5, -.5))
        self.assertEqual(result["input"], [-.375, -.25, -.125])
        self.assertEqual(result["expected_output"], [-.75, -4.0])

    def test_shape_or_nonfinite_cannot_make_witness(self):
        for shape, data in (([2, 2], b"four"), ([1, 1], struct.pack("<f", float("inf")))):
            with self.subTest(shape=shape), self.assertRaises(evidence.EvidenceError):
                checkpoint_bridge.linear_witness(data, shape)

    def test_safetensors_exact_header_and_payload(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "trained.safetensors"
            data = struct.pack("<6f", 1, 2, 3, 4, 5, 6)
            result = checkpoint_bridge.write_safetensors(path, {"layer.weight": {"shape": [2, 3], "data": data}})
            raw = path.read_bytes()
            extent = struct.unpack_from("<Q", raw)[0]
            header = evidence.strict_json(raw[8:8 + extent])
            self.assertEqual(header["layer.weight"], {"dtype": "F32", "shape": [2, 3], "data_offsets": [0, 24]})
            self.assertEqual(raw[8 + extent:], data)
            self.assertEqual(hashlib.sha384(raw).hexdigest(), result["sha384"])

    def test_export_does_not_overwrite_previous_checkpoint(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "existing"
            path.write_bytes(b"old")
            with self.assertRaises(evidence.EvidenceError):
                checkpoint_bridge.write_safetensors(path, {"x": {"shape": [1], "data": b"1234"}})
            self.assertEqual(path.read_bytes(), b"old")

    def source_fixture(self, root):
        checkpoint = root / "trained.safetensors"
        checkpoint.write_bytes(b"test-only checkpoint; signature verification is native")
        checkpoint_meta = {"sha256": evidence.sha256_file(checkpoint), "sha384": hashlib.sha384(checkpoint.read_bytes()).hexdigest(), "bytes": checkpoint.stat().st_size}
        export = root / "export.json"
        export.write_text(json.dumps({"schema": "BTX-TRAINED-NATIVE-EXPORT/1", "artifact_id": "a" * 96,
                                      "checkpoint": checkpoint_meta, "linear": {"weights": "test"}, "training": {"test_only": True}}))
        rows = []
        for key in ("12", "34"):
            public = key * 1312
            receipt = root / (key + ".json")
            receipt.write_text(json.dumps({"receipt": {"artifact_id": "a" * 96,
                                                       "checkpoint_sha384": checkpoint_meta["sha384"],
                                                       "bytes": checkpoint_meta["bytes"], "request_nonce": "b" * 64,
                                                       "source_public_key": public, "signature": "TEST_ONLY"}}))
            rows.append({"path": str(checkpoint), "receipt_path": str(receipt),
                         "receipt_sha256": evidence.sha256_file(receipt), "expected_source_public_key": public})
        sources = root / "sources.json"
        sources.write_text(json.dumps({"schema": "BTX-CHECKPOINT-SOURCES/1", "sources": rows}))
        return export, sources

    def test_bridge_rejects_receipt_from_wrong_challenge(self):
        with tempfile.TemporaryDirectory() as temp:
            export, sources = self.source_fixture(Path(temp))
            with self.assertRaises(evidence.EvidenceError):
                checkpoint_bridge.prepare_native_request(export, evidence.sha256_file(export), sources,
                                                          evidence.sha256_file(sources), "c" * 64)

    def test_bridge_rejects_source_bytes_changed_after_training(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            export, sources = self.source_fixture(root)
            (root / "trained.safetensors").write_bytes(b"changed")
            with self.assertRaises(evidence.EvidenceError):
                checkpoint_bridge.prepare_native_request(export, evidence.sha256_file(export), sources,
                                                          evidence.sha256_file(sources), "b" * 64)

    def test_bridge_requires_independently_pinned_distinct_keys(self):
        with tempfile.TemporaryDirectory() as temp:
            export, sources = self.source_fixture(Path(temp))
            data = json.loads(sources.read_text())
            data["sources"][1] = data["sources"][0]
            sources.write_text(json.dumps(data))
            with self.assertRaises(evidence.EvidenceError):
                checkpoint_bridge.prepare_native_request(export, evidence.sha256_file(export), sources,
                                                          evidence.sha256_file(sources), "b" * 64)


class NativeModelTests(unittest.TestCase):
    def test_model_tree_requires_exact_inventory(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            file = root / "weights.safetensors"
            file.write_bytes(b"test-only weights")
            rows = [{"path": file.name, "sha256": evidence.sha256_file(file), "bytes": file.stat().st_size}]
            self.assertEqual(native_model.verify_model_files(root, rows), rows)
            (root / "unapproved.py").write_text("raise RuntimeError")
            with self.assertRaises(evidence.EvidenceError):
                native_model.verify_model_files(root, rows)

    def test_model_symlink_is_never_a_pinned_tensor(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "real").write_bytes(b"weights")
            (root / "weights.safetensors").symlink_to(root / "real")
            rows = [{"path": "weights.safetensors", "sha256": evidence.sha256_file(root / "real"), "bytes": 7}]
            with self.assertRaises(evidence.EvidenceError):
                native_model.verify_model_files(root, rows)

    def test_guard_self_report_without_live_pid_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            status = Path(temp) / "guard.json"
            status.write_text(json.dumps({"schema": "BTX/GuardProcess/1", "enabled": True, "ready": True,
                                          "pid": 0, "automatic_spend_atoms": "0", "execution_authorized": False}))
            with self.assertRaises(evidence.EvidenceError):
                native_node.observe_guard(status, "a" * 64, 1)

    def test_guard_execution_authority_is_not_implied_by_ready(self):
        with tempfile.TemporaryDirectory() as temp:
            status = Path(temp) / "guard.json"
            status.write_text(json.dumps({"schema": "BTX/GuardProcess/1", "enabled": True, "ready": True,
                                          "pid": 1, "automatic_spend_atoms": "0", "execution_authorized": True}))
            with self.assertRaises(evidence.EvidenceError):
                native_node.observe_guard(status, "a" * 64, 1)


class RuntimeCollectionTests(unittest.TestCase):
    def test_linux_dependencies_include_loader_and_transitive_bytes(self):
        output = "linux-vdso.so.1 (0x0000)\nlibssl.so.3 => /opt/btx/lib/libssl.so.3 (0x1234)\n/lib64/ld-linux-x86-64.so.2 (0xabcd)\n"
        self.assertEqual(collect_runtime.linux_dependencies(output), [("libssl.so.3", "/opt/btx/lib/libssl.so.3"), ("ld-linux-x86-64.so.2", "/lib64/ld-linux-x86-64.so.2")])

    def test_missing_dynamic_library_fails_closed(self):
        with self.assertRaises(evidence.EvidenceError):
            collect_runtime.linux_dependencies("libcrypto.so.3 => not found\n")

    def test_unknown_dependency_output_is_not_silently_ignored(self):
        with self.assertRaises(evidence.EvidenceError):
            collect_runtime.linux_dependencies("unexpected-loader-contract\n")

    def test_mac_rpath_must_resolve_to_pinned_explicit_root(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with self.assertRaises(evidence.EvidenceError):
                collect_runtime.mac_dependencies("btxd:\n\t@rpath/libx.dylib (compatibility version 1.0.0, current version 1.0.0)\n", root / "btxd", [root])

    def test_windows_unresolved_dll_is_not_assumed_present(self):
        with self.assertRaises(evidence.EvidenceError):
            collect_runtime.windows_dependencies("    absent.dll\n", [])

    def test_native_binary_header_must_match_linux_architecture(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "test-only"
            data = bytearray(64)
            data[:6] = b"\x7fELF\x02\x01"
            data[18:20] = (183).to_bytes(2, "little")
            path.write_bytes(data)
            with self.assertRaises(evidence.EvidenceError):
                collect_runtime.check_native_header(path, "linux-x86_64")


class WanPeerTests(unittest.TestCase):
    def test_wan_rejects_private_loopback_reserved_and_unresolved_names(self):
        for endpoint in ("127.0.0.1:29447", "10.1.2.3:29447", "192.0.2.4:29447", "[::1]:29447", "224.0.0.1:29447", "not-an-enrolled-host:29447"):
            with self.subTest(endpoint=endpoint), self.assertRaises(evidence.EvidenceError):
                wan_peers.public_endpoint(endpoint)

    def test_wan_transport_pin_must_equal_independent_enrollment(self):
        enrollment = {"network": "regtest", "peers": [{"endpoint": "enrolled", "transport_pin": "a" * 96}]}
        observed = {"network": "regtest", "peer_observations": [{"endpoint": "enrolled", "transport_pin": "b" * 96, "compute_authorized": False}]}
        with self.assertRaises(evidence.EvidenceError):
            wan_peers.observed_peers(observed, enrollment)

    def test_wan_wrong_chain_cannot_pass(self):
        with self.assertRaises(evidence.EvidenceError):
            wan_peers.observed_peers({"network": "main"}, {"network": "regtest", "peers": []})

    def test_wan_expired_observation_cannot_pass(self):
        enrollment = {"network": "regtest", "peers": [{"endpoint": "enrolled", "transport_pin": "a" * 96}]}
        observed = {"network": "regtest", "peer_observations": [{"endpoint": "enrolled", "transport_pin": "a" * 96,
                                                                 "compute_authorized": False, "observed_at_ms": 1, "expires_at_ms": 90001}]}
        with self.assertRaises(evidence.EvidenceError):
            wan_peers.observed_peers(observed, enrollment)


if __name__ == "__main__":
    unittest.main()
