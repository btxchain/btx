# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see COPYING.
"""Protocol/tool regression tests; these are not native deployment evidence."""

import copy
import csv
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import evidence
import offline_image
import runner
import prepare_plan


class EvidenceTests(unittest.TestCase):
    def test_duplicate_json_keys_rejected(self):
        with self.assertRaises(evidence.EvidenceError):
            evidence.strict_json('{"status":"FAIL","status":"PASS"}')

    def test_nonfinite_json_rejected(self):
        with self.assertRaises(evidence.EvidenceError):
            evidence.strict_json('{"value":NaN}')

    def test_receipt_tampering_rejected(self):
        key = secrets.token_bytes(32)
        receipt = evidence.sign_receipt({"native_status": "NOT_RUN"}, key)
        receipt["body"]["native_status"] = "PASS"
        with self.assertRaises(evidence.EvidenceError):
            evidence.verify_receipt(receipt, key)

    def test_wrong_receipt_key_rejected(self):
        receipt = evidence.sign_receipt({"x": 2}, secrets.token_bytes(32))
        with self.assertRaises(evidence.EvidenceError):
            evidence.verify_receipt(receipt, secrets.token_bytes(32))

    def test_boolean_is_not_numeric_count(self):
        result = evidence.evaluate_assertions({"peers": True}, [{"path": "peers", "op": "min", "value": 1}])
        self.assertFalse(result[0]["passed"])

    def test_missing_observation_cannot_pass(self):
        with self.assertRaises(evidence.EvidenceError):
            evidence.evaluate_assertions({"passed": True}, [{"path": "peers", "op": "min", "value": 2}])

    def test_integer_and_boolean_equality_is_distinct(self):
        outcome = evidence.evaluate_assertions({"count": 1}, [{"path": "count", "op": "eq", "value": True}])
        self.assertFalse(outcome[0]["passed"])

    def test_zero_exit_needs_observed_assertions(self):
        with self.assertRaises(evidence.EvidenceError):
            evidence.evaluate_assertions({"passed": True}, [])

    def test_timeout_terminates_owned_process(self):
        with tempfile.TemporaryDirectory() as temp:
            result = evidence.run_command([sys.executable, "-c", "import time; time.sleep(60)"], Path(temp), timeout=1)
        self.assertEqual(result["failure"], "TIMEOUT")
        self.assertNotEqual(result["returncode"], 0)
        self.assertLess(result["duration_ms"], 10000)

    def test_output_limit_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            result = evidence.run_command([sys.executable, "-c", "print('x'*50000)"], Path(temp), max_output=1024)
        self.assertEqual(result["failure"], "OUTPUT_LIMIT")

    def test_credentials_not_recorded_in_argv(self):
        with self.assertRaises(evidence.EvidenceError):
            evidence.run_command([sys.executable, "-rpcpassword=fixture"], Path.cwd())

    def test_source_digest_binds_uncommitted_changes_and_deletions(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            source = root / "file.cpp"
            source.write_text("original\n")
            subprocess.run(["git", "-C", str(root), "add", "."], check=True)
            subprocess.run(["git", "-C", str(root), "-c", "user.name=Test", "-c", "user.email=test@invalid", "commit", "-qm", "fixture"], check=True)
            one = evidence.source_identity(root)
            source.write_text("changed\n")
            two = evidence.source_identity(root)
            source.unlink()
            three = evidence.source_identity(root)
            self.assertEqual(one["commit"], two["commit"])
            self.assertEqual(len({one["source_tree_sha256"], two["source_tree_sha256"], three["source_tree_sha256"]}), 3)

    def test_executable_pin_checked_before_execution(self):
        step = {"id": "wrong", "host": "local", "argv": [sys.executable, "-c", "print('{}')"],
                "executable_sha256": "0" * 64, "assertions": [{"path": "x", "op": "eq", "value": 1}]}
        with self.assertRaises(evidence.EvidenceError):
            runner.execute_step(Path.cwd(), step, "a" * 64)

    def test_observed_command_is_recorded_and_evaluated(self):
        executable = str(Path(sys.executable).resolve())
        step = {"id": "measurement", "host": "local", "argv": [executable, "-c", "import json; print(json.dumps({'bytes':12}))"],
                "executable_sha256": evidence.sha256_file(Path(executable)),
                "assertions": [{"path": "bytes", "op": "min", "value": 10}], "requirements": ["TEST-ONLY"]}
        result = runner.execute_step(Path.cwd(), step, "a" * 64)
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["checks"][0]["observed"], 12)
        self.assertEqual(result["inputs"][0]["sha256"], step["executable_sha256"])


class OfflineTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.lock = {"schema": "BTX-OFFLINE-LOCK/1", "platform": "linux-x86_64",
                     "source_commit": "1" * 40, "source_tree_sha256": "2" * 64,
                     "files": [], "dependency_closure": ["lib/runtime-fixture.txt"]}
        for name in offline_image.REQUIRED:
            path = self.root / name
            path.write_bytes(("test-fixture-" + name).encode())
            self.lock["files"].append({"source": str(path), "path": "bin/" + name,
                                        "sha256": evidence.sha256_file(path), "executable": True})
        runtime = self.root / "runtime.txt"
        runtime.write_bytes(b"dependency fixture; no native qualification")
        self.lock["files"].append({"source": str(runtime), "path": "lib/runtime-fixture.txt",
                                    "sha256": evidence.sha256_file(runtime), "executable": False})

    def tearDown(self):
        self.temporary.cleanup()

    def test_deterministic_archive_and_verified_extract(self):
        first = offline_image.build(self.lock, self.root / "one.tar.gz")
        second = offline_image.build(self.lock, self.root / "two.tar.gz")
        self.assertEqual(first["sha256"], second["sha256"])
        verified = offline_image.verify(self.root / "one.tar.gz", first["sha256"], self.root / "unpacked")
        self.assertEqual(verified["files_verified"], 6)
        self.assertEqual(verified["native_qualification"], "NOT_RUN")
        self.assertEqual((self.root / "unpacked/bin/btxd").read_bytes(), b"test-fixture-btxd")

    def test_input_pin_mismatch_rejected(self):
        self.lock["files"][0]["sha256"] = "0" * 64
        with self.assertRaises(evidence.EvidenceError):
            offline_image.build(self.lock, self.root / "bad.tar.gz")

    def test_missing_helper_rejected(self):
        self.lock["files"] = [entry for entry in self.lock["files"] if entry["path"] != "bin/btx-hcpd"]
        with self.assertRaises(evidence.EvidenceError):
            offline_image.build(self.lock, self.root / "bad.tar.gz")

    def test_declared_dependency_must_exist(self):
        self.lock["dependency_closure"].append("lib/absent.so")
        with self.assertRaises(evidence.EvidenceError):
            offline_image.build(self.lock, self.root / "bad.tar.gz")

    def test_path_traversal_rejected(self):
        for name in ("../outside", "/absolute", "bin/../outside", "C:/Windows/file", "bin\\outside", "bin//outside"):
            with self.subTest(name=name), self.assertRaises(evidence.EvidenceError):
                offline_image.safe_name(name)

    def test_case_insensitive_path_collision_rejected(self):
        entry = copy.deepcopy(self.lock["files"][0])
        entry["path"] = "BIN/BTXD"
        self.lock["files"].append(entry)
        with self.assertRaises(evidence.EvidenceError):
            offline_image.build(self.lock, self.root / "bad.tar.gz")

    def test_symlink_input_rejected(self):
        target = self.root / "link"
        target.symlink_to(self.root / "btxd")
        self.lock["files"][0]["source"] = str(target)
        with self.assertRaises(evidence.EvidenceError):
            offline_image.build(self.lock, self.root / "bad.tar.gz")

    def test_archive_hash_mismatch_rejected(self):
        offline_image.build(self.lock, self.root / "one.tar.gz")
        with self.assertRaises(evidence.EvidenceError):
            offline_image.verify(self.root / "one.tar.gz", "0" * 64)

    def test_existing_extraction_destination_not_overwritten(self):
        receipt = offline_image.build(self.lock, self.root / "one.tar.gz")
        destination = self.root / "existing"
        destination.mkdir()
        (destination / "user-file").write_text("keep")
        with self.assertRaises(evidence.EvidenceError):
            offline_image.verify(self.root / "one.tar.gz", receipt["sha256"], destination)
        self.assertEqual((destination / "user-file").read_text(), "keep")

    def test_link_archive_rejected_without_extraction(self):
        archive_path = self.root / "malicious.tar.gz"
        with tarfile.open(archive_path, "w:gz") as archive:
            member = tarfile.TarInfo("manifest.json")
            member.type = tarfile.SYMTYPE
            member.linkname = "/etc/passwd"
            archive.addfile(member)
        with self.assertRaises(evidence.EvidenceError):
            offline_image.verify(archive_path, evidence.sha256_file(archive_path), self.root / "output")
        self.assertFalse((self.root / "output").exists())

    def test_archive_cannot_inject_members_between_verify_and_extract(self):
        receipt = offline_image.build(self.lock, self.root / "one.tar.gz")
        swapped = self.root / "swapped.tar.gz"
        original_open = tarfile.open
        with original_open(self.root / "one.tar.gz", "r:gz") as source, original_open(swapped, "w:gz") as target:
            for member in source:
                target.addfile(member, source.extractfile(member))
            payload = b"unapproved runtime module"
            member = offline_image._tar_info("lib/unapproved.py", len(payload))
            target.addfile(member, io.BytesIO(payload))
        calls = 0

        def reopen(path, *args, **kwargs):
            nonlocal calls
            calls += 1
            return original_open(swapped if calls == 2 else path, *args, **kwargs)

        with mock.patch.object(offline_image.tarfile, "open", side_effect=reopen):
            with self.assertRaises(evidence.EvidenceError):
                offline_image.verify(self.root / "one.tar.gz", receipt["sha256"], self.root / "output")
        self.assertFalse((self.root / "output").exists())


class GateTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.catalogue = self.root / "sealed.json"
        self.catalogue.write_text(json.dumps([{"id": "ROW-" + str(i)} for i in range(1, 574)]))
        self.key = secrets.token_bytes(32)
        self.source = {"commit": "1" * 40, "source_tree_sha256": "2" * 64, "source_files": 1}
        self.plan = "3" * 64
        self.policy = {"schema": "BTX-NATIVE-GATE/1", "catalogue_sha256": evidence.sha256_file(self.catalogue),
                       "catalogue_rows": 573, "source": self.source, "row_plans": {"ROW-" + str(i): [self.plan] for i in range(1, 574)},
                       "machine_enrollment": {"4" * 64: {"physical_host_id": "fixture-host", "gpu_uuids": []}},
                       "profile_rules": {name: {"plan_sha256": [self.plan]} for name in runner.PROFILES}}

    def tearDown(self):
        self.temporary.cleanup()

    def receipt(self, profile="fresh-native-start"):
        nonce = secrets.token_hex(32)
        assertion = {"path": "bytes", "op": "min", "value": 1}
        body = {"schema": evidence.SCHEMA, "status": "PASS", "source": self.source, "nonce": nonce,
                "plan_sha256": self.plan, "profile": profile, "finished_ns": time.time_ns(),
                "hosts": {"host": {"nonce": nonce, "source": self.source, "machine_id_sha256": "4" * 64, "gpus": []}},
                "steps": [{"status": "PASS", "returncode": 0, "failure": "", "nonce": nonce,
                           "stdout": '{"bytes":5}', "checks": [{"passed": True}], "assertions": [assertion],
                           "requirements": ["ROW-1"], "inputs": [{"sha256": "5" * 64}]}]}
        return evidence.sign_receipt(body, self.key)

    def test_one_passing_profile_does_not_qualify_release(self):
        result = runner.release_gate(self.policy, self.catalogue, [self.receipt()], self.key)
        self.assertFalse(result["qualified"])
        self.assertEqual(result["covered_rows"], 1)
        self.assertEqual(len(result["missing_profiles"]), 31)

    def test_catalogue_cannot_be_shrunk(self):
        self.catalogue.write_text("[]")
        with self.assertRaises(evidence.EvidenceError):
            runner.release_gate(self.policy, self.catalogue, [], self.key)

    def test_unpinned_rows_rejected(self):
        self.policy["row_plans"] = {}
        with self.assertRaises(evidence.EvidenceError):
            runner.release_gate(self.policy, self.catalogue, [], self.key)

    def test_duplicate_receipt_cannot_inflate_evidence(self):
        receipt = self.receipt()
        result = runner.release_gate(self.policy, self.catalogue, [receipt, receipt], self.key)
        self.assertFalse(result["qualified"])
        self.assertTrue(any("duplicate" in reason for reason in result["rejected_receipts"]))

    def test_one_machine_cannot_qualify_lan(self):
        result = runner.release_gate(self.policy, self.catalogue, [self.receipt("lan-two-physical-hosts")], self.key)
        self.assertTrue(any("insufficient" in reason for reason in result["rejected_receipts"]))
        self.assertFalse(result["qualified"])

    def test_candidate_changes_invalidate_receipts(self):
        receipt = self.receipt()
        self.policy["source"] = dict(self.source, source_tree_sha256="9" * 64)
        result = runner.release_gate(self.policy, self.catalogue, [receipt], self.key)
        self.assertTrue(any("another candidate" in reason for reason in result["rejected_receipts"]))

    def test_stale_receipt_rejected(self):
        receipt = self.receipt()
        receipt["body"]["finished_ns"] = time.time_ns() - 2 * 86400 * 1_000_000_000
        receipt = evidence.sign_receipt(receipt["body"], self.key)
        result = runner.release_gate(self.policy, self.catalogue, [receipt], self.key)
        self.assertTrue(any("stale" in reason for reason in result["rejected_receipts"]))

    def test_future_receipt_rejected(self):
        receipt = self.receipt()
        receipt["body"]["finished_ns"] = time.time_ns() + 3600 * 1_000_000_000
        receipt = evidence.sign_receipt(receipt["body"], self.key)
        result = runner.release_gate(self.policy, self.catalogue, [receipt], self.key)
        self.assertTrue(any("future" in reason for reason in result["rejected_receipts"]))

    def test_ascend_profile_cannot_use_nvidia_presence_as_npu_evidence(self):
        receipt = self.receipt("linux-ascend-deepinfer")
        result = runner.release_gate(self.policy, self.catalogue, [receipt], self.key)
        self.assertTrue(any("Ascend" in reason for reason in result["rejected_receipts"]))

    def test_small_catalogue_cannot_qualify_full_screenshot_scope(self):
        self.catalogue.write_text('[{"id":"ROW-1"}]')
        self.policy["catalogue_sha256"] = evidence.sha256_file(self.catalogue)
        self.policy["catalogue_rows"] = 1
        self.policy["row_plans"] = {"ROW-1": [self.plan]}
        with self.assertRaises(evidence.EvidenceError):
            runner.release_gate(self.policy, self.catalogue, [self.receipt()], self.key)

    def test_caller_passed_boolean_does_not_override_measurement(self):
        receipt = self.receipt()
        receipt["body"]["steps"][0]["stdout"] = '{"bytes":0,"passed":true,"release_qualified":true}'
        receipt = evidence.sign_receipt(receipt["body"], self.key)
        result = runner.release_gate(self.policy, self.catalogue, [receipt], self.key)
        self.assertTrue(any("observed native outputs" in reason for reason in result["rejected_receipts"]))

    def test_all_profiles_cannot_be_removed_from_policy(self):
        self.policy["required_profiles"] = ["fresh-native-start"]
        with self.assertRaises(evidence.EvidenceError):
            runner.release_gate(self.policy, self.catalogue, [self.receipt()], self.key)

    def test_screenshot_inventory_is_complete_and_not_promoted(self):
        inventory = json.loads((Path(__file__).resolve().parents[1] / "SCREENSHOT_REQUIREMENTS.json").read_text())
        self.assertEqual(len(inventory["requirements"]), 210)
        self.assertEqual(sum(row["screenshot_status"] == "OPEN_BEHAVIOR" for row in inventory["requirements"]), 21)
        self.assertEqual(len({row["id"] for row in inventory["requirements"]}), 210)
        self.assertEqual(len(inventory["profiles"]), 32)
        self.assertTrue(all(row["native_status"] == "NOT_RUN_NATIVE" for row in inventory["requirements"]))


class PlanTests(unittest.TestCase):
    def member(self, machine):
        executable = str(Path(sys.executable).resolve())
        return {"schema": "BTX-NATIVE-PLAN/1", "profile": "lan-two-physical-hosts",
                "source": {"commit": "1" * 40, "source_tree_sha256": "2" * 64},
                "hosts": {"node": {"transport": "local", "root": "/test-repo", "machine_id_sha256": machine}},
                "phases": [{"name": "run", "steps": [{"id": "native", "host": "node", "argv": [executable, "-c", "print('{}')"],
                            "executable_sha256": "3" * 64, "requirements": ["P2P-SCN-B"],
                            "assertions": [{"path": "network.peers", "op": "min", "value": 1}]}]}]}

    def test_merge_keeps_native_hosts_parallel_and_distinct(self):
        a, b = self.member("4" * 64), self.member("5" * 64)
        result = prepare_plan.merge({"a": a, "b": b}, {"a": a["hosts"]["node"], "b": b["hosts"]["node"]})
        self.assertEqual(set(result["hosts"]), {"a", "b"})
        self.assertEqual([step["host"] for step in result["phases"][0]["steps"]], ["a", "b"])
        self.assertEqual(len({step["id"] for step in result["phases"][0]["steps"]}), 2)

    def test_same_machine_two_processes_refused_as_two_hosts(self):
        a, b = self.member("4" * 64), self.member("4" * 64)
        with self.assertRaises(evidence.EvidenceError):
            prepare_plan.merge({"a": a, "b": b}, {"a": a["hosts"]["node"], "b": b["hosts"]["node"]})

    def test_different_candidates_cannot_merge(self):
        a, b = self.member("4" * 64), self.member("5" * 64)
        b["source"]["source_tree_sha256"] = "6" * 64
        with self.assertRaises(evidence.EvidenceError):
            prepare_plan.merge({"a": a, "b": b}, {"a": a["hosts"]["node"], "b": b["hosts"]["node"]})

    def test_changed_enrollment_refused(self):
        a = self.member("4" * 64)
        configuration = dict(a["hosts"]["node"], machine_id_sha256="9" * 64)
        with self.assertRaises(evidence.EvidenceError):
            prepare_plan.merge({"a": a}, {"a": configuration})


if __name__ == "__main__":
    unittest.main()
