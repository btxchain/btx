#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Fail-closed integration tests for run-full-benchmark.py."""

import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest


WRAPPER = Path(__file__).with_name("run-full-benchmark.py")


class FullBenchmarkWrapperTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def harness(self, behavior):
        path = self.tmp_path / f"harness-{behavior}.py"
        path.write_text(textwrap.dedent(f"""\
            #!/usr/bin/env python3
            import json
            import sys
            import time

            behavior = {behavior!r}
            if behavior == "nonzero":
                raise SystemExit(19)
            if behavior == "timeout":
                time.sleep(5)
                raise SystemExit(0)

            args = sys.argv[1:]
            out = args[args.index("--out") + 1]
            backend = args[args.index("--backend") + 1]
            episodes = int(args[args.index("--episodes") + 1])
            production = "--base-production" in args or "--production" in args or \
                "--coupled-production-v2" in args
            if behavior == "no-report":
                raise SystemExit(0)
            if behavior == "malformed":
                with open(out, "w", encoding="utf-8") as f:
                    f.write("{{not-json")
                raise SystemExit(0)

            report = {{
                "tool": "rc-episode-harness",
                "schema_version": 2,
                "stub": False,
                "backend": backend,
                "backend_requested": backend,
                "production_dims": production,
                "extractmx_self_qual": {{
                    "status": "pass",
                    "episodes": episodes,
                }},
                "phase_wall_s": {{"total": 0.01}},
                "digest": "00",
            }}
            if behavior == "failed":
                report["extractmx_self_qual"]["status"] = "fail"
            if behavior == "invalid-schema":
                del report["phase_wall_s"]
            if behavior == "require-cuda" and backend != "cuda":
                raise SystemExit(23)
            with open(out, "w", encoding="utf-8") as f:
                json.dump(report, f)
        """), encoding="utf-8")
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
        return path

    def run_wrapper(self, *args):
        return subprocess.run(
            [sys.executable, str(WRAPPER), *map(str, args)],
            text=True,
            capture_output=True,
            timeout=20,
            env={**os.environ, "NO_COLOR": "1"},
        )

    def test_nonzero_harness_fails(self):
        result = self.run_wrapper(
            "--harness", self.harness("nonzero"), "--quick")
        self.assertEqual(result.returncode, 5, result.stdout + result.stderr)

    def test_timeout_fails_distinctly(self):
        result = self.run_wrapper(
            "--harness", self.harness("timeout"), "--quick",
            "--timeout-seconds", "0.05")
        self.assertEqual(result.returncode, 4, result.stdout + result.stderr)

    def test_invocation_failure_fails_distinctly(self):
        harness = self.tmp_path / "not-executable"
        harness.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        result = self.run_wrapper("--harness", harness, "--quick")
        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)

    def test_exit_zero_without_report_fails(self):
        result = self.run_wrapper(
            "--harness", self.harness("no-report"), "--quick")
        self.assertEqual(result.returncode, 6, result.stdout + result.stderr)

    def test_malformed_json_fails(self):
        result = self.run_wrapper(
            "--harness", self.harness("malformed"), "--quick")
        self.assertEqual(result.returncode, 6, result.stdout + result.stderr)

    def test_schema_invalid_json_fails(self):
        result = self.run_wrapper(
            "--harness", self.harness("invalid-schema"), "--quick")
        self.assertEqual(result.returncode, 6, result.stdout + result.stderr)

    def test_failed_report_fails(self):
        result = self.run_wrapper(
            "--harness", self.harness("failed"), "--quick")
        self.assertEqual(result.returncode, 6, result.stdout + result.stderr)

    def test_valid_report_succeeds_and_is_copied(self):
        output = self.tmp_path / "accepted.json"
        result = self.run_wrapper(
            "--harness", self.harness("valid"), "--quick", "--json", output)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(output.exists())
        self.assertEqual(json.loads(output.read_text(encoding="utf-8"))["tool"],
                         "rc-episode-harness")
        self.assertIn("This run measured", result.stdout)

    def test_production_auto_requires_explicit_opt_in(self):
        result = self.run_wrapper("--harness", self.harness("valid"))
        self.assertEqual(result.returncode, 7, result.stdout + result.stderr)
        self.assertIn("Refusing production --backend auto", result.stdout)

    def test_explicit_accelerator_reaches_harness_unchanged(self):
        result = self.run_wrapper(
            "--harness", self.harness("require-cuda"),
            "--shape", "production", "--backend", "cuda")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("backend=cuda", result.stdout)


if __name__ == "__main__":
    unittest.main()
