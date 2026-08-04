#!/usr/bin/env python3
"""Fail-closed tests for MatMul evidence provenance binding."""

from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "contrib/matmul-v4/verify-evidence-provenance.py"


class EvidenceProvenanceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.evidence = self.root / "doc/evidence"
        self.evidence.mkdir(parents=True)
        (self.root / "cmake").mkdir()
        (self.root / "src").mkdir()
        (self.root / "CMakeLists.txt").write_text("project(test)\n")
        (self.root / "cmake/config.cmake").write_text("set(TEST 1)\n")
        (self.root / "src/value.cpp").write_text("int value = 1;\n")
        self.git("init", "-q")
        self.git("config", "user.name", "Evidence Test")
        self.git("config", "user.email", "evidence-test@example.invalid")
        self.git("add", ".")
        self.git("commit", "-qm", "first")
        self.revision_a = self.git("rev-parse", "HEAD").stdout.strip()
        self.fingerprint_a = self.fingerprint(self.revision_a)

        (self.root / "src/value.cpp").write_text("int value = 2;\n")
        self.git("add", "src/value.cpp")
        self.git("commit", "-qm", "second")
        self.revision_b = self.git("rev-parse", "HEAD").stdout.strip()
        self.fingerprint_b = self.fingerprint(self.revision_b)
        self.main_branch = self.git("branch", "--show-current").stdout.strip()
        self.write_exclusions([])

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def git(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", "-C", str(self.root), *args],
            capture_output=True,
            text=True,
            check=True,
        )

    def fingerprint(self, revision: str) -> str:
        tree = subprocess.run(
            [
                "git", "-C", str(self.root), "ls-tree", "-r", "--full-tree",
                revision, "--", "CMakeLists.txt", "cmake", "src",
            ],
            capture_output=True,
            check=True,
        ).stdout
        return hashlib.sha256(tree).hexdigest()

    @property
    def exclusions(self) -> Path:
        return self.root / "exclusions.json"

    def write_exclusions(self, entries: list[dict]) -> None:
        self.exclusions.write_text(json.dumps({
            "schema_version": 1,
            "exclusions": entries,
        }))

    def write_evidence(self, payload: object, name: str = "report.json") -> Path:
        path = self.evidence / name
        path.write_text(json.dumps(payload))
        return path

    def run_verify(self, *, strict: bool = True) -> subprocess.CompletedProcess[str]:
        command = [
            "python3", str(SCRIPT), "--root", str(self.root),
            "--evidence-dir", "doc/evidence", "--exclusions",
            str(self.exclusions),
        ]
        if strict:
            command.append("--strict")
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
        )

    def create_matching_side_branch_revision(self) -> tuple[str, str]:
        self.git("checkout", "-qb", "historical-side", self.revision_a)
        (self.root / "src/value.cpp").write_text("int value = 3;\n")
        self.git("add", "src/value.cpp")
        self.git("commit", "-qm", "historical side branch")
        revision = self.git("rev-parse", "HEAD").stdout.strip()
        fingerprint = self.fingerprint(revision)
        self.git("checkout", "-q", self.main_branch)
        return revision, fingerprint

    def test_matching_object_local_pairs_pass(self) -> None:
        self.write_evidence({
            "first": {
                "source_revision": self.revision_a,
                "source_tree_fingerprint": self.fingerprint_a,
            },
            "second": {
                "source_revision": self.revision_b,
                "source_tree_fingerprint": self.fingerprint_b,
            },
        })
        result = self.run_verify()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_cross_object_swapped_fingerprints_fail(self) -> None:
        # A document-wide set comparison would incorrectly accept these four
        # individually real values. Each object binds the wrong pair.
        self.write_evidence({
            "first": {
                "source_revision": self.revision_a,
                "source_tree_fingerprint": self.fingerprint_b,
            },
            "second": {
                "source_revision": self.revision_b,
                "source_tree_fingerprint": self.fingerprint_a,
            },
        })
        result = self.run_verify()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not match revision", result.stdout)

    def test_explicit_historical_exclusion_is_visible_and_passes(self) -> None:
        relative = "doc/evidence/historical.json"
        self.write_evidence({"source_revision": "unknown"}, "historical.json")
        self.write_exclusions([{
            "evidence_path": relative,
            "revision": "unknown",
            "reason": "historical diagnostic did not capture a commit",
            "production_admissible": False,
        }])
        result = self.run_verify()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("EXCLUDED", result.stdout)
        self.assertIn("production_admissible=false", result.stdout)

    def test_matching_side_branch_revision_fails_strict(self) -> None:
        revision, fingerprint = self.create_matching_side_branch_revision()
        self.write_evidence({
            "source_revision": revision,
            "source_tree_fingerprint": fingerprint,
        })

        non_strict = self.run_verify(strict=False)
        self.assertEqual(
            non_strict.returncode, 0, non_strict.stdout + non_strict.stderr
        )

        strict = self.run_verify()
        self.assertNotEqual(strict.returncode, 0)
        self.assertIn("is not reachable from HEAD", strict.stdout)

    def test_excluded_side_branch_revision_is_visible_and_passes(self) -> None:
        revision, fingerprint = self.create_matching_side_branch_revision()
        relative = "doc/evidence/historical-side.json"
        self.write_evidence({
            "source_revision": revision,
            "source_tree_fingerprint": fingerprint,
        }, "historical-side.json")
        self.write_exclusions([{
            "evidence_path": relative,
            "revision": revision,
            "reason": "historical side-branch diagnostic",
            "production_admissible": False,
        }])

        result = self.run_verify()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("EXCLUDED", result.stdout)
        self.assertIn("production_admissible=false", result.stdout)

    def test_symbolic_link_evidence_fails(self) -> None:
        target = self.root / "outside-evidence.json"
        target.write_text(json.dumps({"source_revision": self.revision_b}))
        (self.evidence / "linked.json").symlink_to(target)

        result = self.run_verify()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("symbolic-link evidence is not allowed", result.stdout)

    def test_symbolic_link_exclusion_registry_fails(self) -> None:
        target = self.root / "outside-exclusions.json"
        target.write_text(json.dumps({"schema_version": 1, "exclusions": []}))
        self.exclusions.unlink()
        self.exclusions.symlink_to(target)

        result = self.run_verify()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("symbolic links are not allowed", result.stdout)

    def test_stale_exclusion_fails_strict(self) -> None:
        self.write_evidence({"source_revision": self.revision_a})
        self.write_exclusions([{
            "evidence_path": "doc/evidence/missing.json",
            "revision": "unknown",
            "reason": "stale test entry",
            "production_admissible": False,
        }])
        result = self.run_verify()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unused historical exclusion", result.stdout)


if __name__ == "__main__":
    unittest.main()
