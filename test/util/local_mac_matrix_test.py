#!/usr/bin/env python3
"""Regression coverage for the local-only validation matrix manifest."""

from __future__ import annotations

import re
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
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


class LocalMacMatrixReceiptTest(unittest.TestCase):
    def fixture_run(self, *, dirty=False, allow_dirty=False, write_failure=False):
        with tempfile.TemporaryDirectory(prefix="matrix-receipt-") as tmp:
            root = Path(tmp)
            repo = root / "repo"
            scripts = repo / "scripts" / "ci"
            scripts.mkdir(parents=True)
            shutil.copyfile(RUNNER, scripts / RUNNER.name)
            manifest = scripts / "local-mac-matrix.tsv"
            manifest.write_text("ci|1|probe|receipt-probe|1\nreadiness|1|probe|receipt-probe|1\n")
            dispatcher = scripts / "run_ci_target.sh"
            dispatcher.write_text('#!/bin/bash\nprintf executed > "$PROBE_MARKER"\n')
            dispatcher.chmod(0o755)
            note = repo / "note.txt"
            note.write_text("committed\n")

            def git(*args):
                return subprocess.check_output([
                    "git", "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false",
                    "-c", "user.name=Receipt Fixture", "-c", "user.email=fixture@example.invalid",
                    "-C", str(repo), *args], text=True).strip()

            git("init", "-q")
            git("add", ".")
            git("commit", "-qm", "fixture")
            commit = git("rev-parse", "HEAD")
            if dirty:
                note.write_text("uncommitted\n")
                manifest.write_text(manifest.read_text() + "# working-tree selection\n")
            tools = root / "tools"
            tools.mkdir()
            for name in ("uname", "sw_vers", "clang", "cmake", "docker", "python3.11"):
                script = tools / name
                script.write_text('#!/bin/sh\nprintf "Darwin\\n"\n')
                script.chmod(0o755)
            date = tools / "date"
            date.write_text('#!/bin/sh\nif [ "$2" = "+%Y%m%dT%H%M%SZ" ]; then '
                            'echo 20000101T000000Z; else exec /bin/date "$@"; fi\n')
            date.chmod(0o755)
            temp = root / "tmp"
            temp.mkdir()
            result_dir = temp / "btx-local-mac-matrix" / "20000101T000000Z"
            if write_failure:
                (result_dir / "run.json").mkdir(parents=True)
            marker = root / "job-executed"
            env = dict(os.environ, TMPDIR=str(temp), PROBE_MARKER=str(marker),
                       PATH=str(tools) + os.pathsep + os.environ["PATH"], GIT_TERMINAL_PROMPT="0")
            args = ["bash", str(scripts / RUNNER.name), "readiness", "--parallel", "1", "--only", "receipt-probe"]
            if allow_dirty:
                args.append("--allow-dirty-head")
            run = subprocess.run(args, cwd=repo, env=env, capture_output=True, text=True, timeout=30)
            if write_failure:
                self.assertNotEqual(run.returncode, 0, run.stdout + run.stderr)
                self.assertFalse(marker.exists(), "receipt failure must precede dispatch")
                self.assertIn("run.json", run.stderr)
                return
            if dirty and not allow_dirty:
                self.assertNotEqual(run.returncode, 0)
                self.assertIn("uncommitted tracked changes", run.stderr)
                self.assertFalse(marker.exists())
                self.assertFalse((result_dir / "run.json").exists())
                return
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            self.assertTrue(marker.exists())
            receipt = json.loads((result_dir / "run.json").read_text())
            self.assertEqual(receipt["source_commit"], commit)
            self.assertEqual(receipt["manifest_sha256"], hashlib.sha256(manifest.read_bytes()).hexdigest())
            self.assertEqual(receipt["manifest_path"], "scripts/ci/local-mac-matrix.tsv")
            self.assertEqual(receipt["mode"], "readiness")
            self.assertEqual(receipt["allow_dirty_head"], allow_dirty)
            self.assertEqual(receipt["tracked_dirty"], dirty)
            self.assertEqual(receipt["schema_version"], 1)
            self.assertEqual(receipt["run_id"], "20000101T000000Z")
            lines = (result_dir / "summary.tsv").read_text().splitlines()
            self.assertEqual(len(lines), 2)
            self.assertEqual(len(lines[0].split("\t")), 11)
            self.assertEqual(len(lines[1].split("\t")), 11)
            self.assertEqual(lines[1].split("\t")[4], "PASS")
            self.assertFalse(Path(lines[1].split("\t")[-1]).exists(), "worktree should be cleaned")
            meta = next((result_dir / "jobs").glob("*/meta.tsv")).read_text().rstrip("\n")
            self.assertEqual(len(meta.split("\t")), 9)

    def test_source_receipt_survives_worktree_cleanup(self):
        self.fixture_run()

    def test_dirty_source_is_rejected_by_default(self):
        self.fixture_run(dirty=True)

    def test_explicit_head_mode_records_actual_manifest_and_dirty_state(self):
        self.fixture_run(dirty=True, allow_dirty=True)

    def test_receipt_write_failure_prevents_dispatch(self):
        self.fixture_run(write_failure=True)


if __name__ == "__main__":
    unittest.main()
