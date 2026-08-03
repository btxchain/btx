#!/usr/bin/env python3
"""Regression coverage for the local-only validation matrix manifest."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
MANIFEST = REPO_ROOT / "scripts" / "ci" / "local-mac-matrix.tsv"
RUNNER = REPO_ROOT / "scripts" / "ci" / "run_local_mac_matrix.sh"
DISPATCHER = REPO_ROOT / "scripts" / "ci" / "run_ci_target.sh"


class LocalMacMatrixTest(unittest.TestCase):
    def manifest_rows(self) -> list[tuple[str, int, str, str, int]]:
        rows: list[tuple[str, int, str, str, int]] = []
        for line_number, raw_line in enumerate(
            MANIFEST.read_text(encoding="utf-8").splitlines(), start=1
        ):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            fields = [field.strip() for field in line.split("|")]
            self.assertEqual(len(fields), 5, f"manifest line {line_number}")
            workflow, max_parallel, job_name, target, timeout_minutes = fields
            self.assertIn(workflow, {"ci", "readiness"})
            self.assertRegex(max_parallel, r"^[1-9][0-9]*$")
            self.assertTrue(job_name)
            self.assertRegex(target, r"^[a-z0-9-]+$")
            self.assertRegex(timeout_minutes, r"^[1-9][0-9]*$")
            rows.append(
                (workflow, int(max_parallel), job_name, target, int(timeout_minutes))
            )
        return rows

    def test_manifest_schema_and_uniqueness(self) -> None:
        rows = self.manifest_rows()
        self.assertGreater(len(rows), 1)
        identities = [(workflow, job_name, target) for workflow, _, job_name, target, _ in rows]
        self.assertEqual(len(identities), len(set(identities)))
        for workflow in {row[0] for row in rows}:
            limits = {row[1] for row in rows if row[0] == workflow}
            self.assertEqual(len(limits), 1, workflow)

    def test_every_manifest_target_has_a_dispatch_case(self) -> None:
        dispatcher = DISPATCHER.read_text(encoding="utf-8")
        cases = set(re.findall(r"^  ([a-z0-9-]+)\)$", dispatcher, re.MULTILINE))
        targets = {row[3] for row in self.manifest_rows()}
        self.assertEqual(targets - cases, set())

    def test_metadata_is_parsed_as_data(self) -> None:
        runner = RUNNER.read_text(encoding="utf-8")
        self.assertIn('> "${job_dir}/meta.tsv"', runner)
        self.assertIn("IFS=$'\\t' read -r workflow job_name target", runner)
        self.assertNotRegex(runner, r"(?m)^\s*source\s+.*meta")
        self.assertNotIn("meta.env", runner)
        self.assertIn("incomplete local-matrix metadata", runner)

    def test_manifest_contains_spaced_job_name_regression_vector(self) -> None:
        rows = self.manifest_rows()
        self.assertTrue(any(" " in row[2] for row in rows))


if __name__ == "__main__":
    unittest.main()
