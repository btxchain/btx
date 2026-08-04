#!/usr/bin/env python3
"""Regression tests for the public MatMul evidence privacy gate."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "contrib/matmul-v4/check-public-evidence.py"
SANITIZER = REPO_ROOT / "contrib/matmul-v4/sanitize-public-evidence.py"
SPEC = importlib.util.spec_from_file_location("check_public_evidence", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class PublicEvidencePrivacyTest(unittest.TestCase):
    def write(self, root: Path, name: str, value: object) -> Path:
        path = root / name
        if isinstance(value, str):
            path.write_text(value, encoding="utf-8")
        else:
            path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def test_sanitized_machine_class_passes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.write(
                Path(directory),
                "report.json",
                {
                    "hardware": "NVIDIA consumer Blackwell-class GPU",
                    "provider": "cuda_rc_exact_fused_extract",
                    "source_revision": "0123456789abcdef",
                },
            )
            self.assertEqual(MODULE.check_file(path), [])

    def test_creator_paths_and_identity_keys_fail(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = self.write(
                root,
                "report.json",
                {
                    "hostname": "validator-01",
                    "log": "/Users/" + "fixture-operator/private-build/run.log",
                },
            )
            failures = MODULE.check_file(path)
            self.assertTrue(any("hostname" in failure for failure in failures))
            self.assertTrue(any("macOS user path" in failure for failure in failures))

    def test_secret_and_email_text_fail(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.write(
                Path(directory),
                "README.md",
                "contact operator@example.invalid; token file github.key\n",
            )
            failures = MODULE.check_file(path)
            self.assertTrue(any("email address" in failure for failure in failures))
            self.assertTrue(any("private key filename" in failure for failure in failures))

    def test_mdns_hostname_hidden_inside_device_id_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.write(
                Path(directory),
                "report.json",
                {
                    "device_id": "metal-provider:validator-workstation.local",
                    "hardware": "Apple Silicon M4 Max-class Metal",
                },
            )
            failures = MODULE.check_file(path)
            self.assertTrue(any("mDNS hostname" in failure for failure in failures))

    def test_soak_sanitizer_emits_nonempty_valid_redacted_json(self) -> None:
        payload = {
            "event": "validation",
            "linux_log": "/" + "home" + "/creator/private/run.log",
            "mac_log": "/" + "Users" + "/creator/private/run.log",
            "host": "private-validator.example",
        }
        environment = os.environ.copy()
        environment["BTX_SANITIZE_EXTRA_HOSTS"] = "private-validator.example"
        result = subprocess.run(
            ["python3", str(SANITIZER)],
            input=json.dumps(payload) + "\n",
            capture_output=True,
            text=True,
            env=environment,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(result.stdout.strip())
        sanitized = json.loads(result.stdout)
        self.assertEqual(sanitized["event"], "validation")
        self.assertNotIn("creator", result.stdout)
        self.assertNotIn("private-validator.example", result.stdout)
        with tempfile.TemporaryDirectory() as directory:
            path = self.write(Path(directory), "sanitized.json", sanitized)
            self.assertEqual(MODULE.check_file(path), [])

    def test_complete_committed_publication_set_is_clean(self) -> None:
        files = list(MODULE.evidence_files(MODULE.DEFAULT_PATHS))
        self.assertGreater(len(files), 50)
        self.assertIn(
            REPO_ROOT / "contrib/matmul-v4/assemble-epoch-a-asert-corpus.py",
            files,
        )
        failures = [
            failure
            for path in files
            for failure in MODULE.check_file(path)
        ]
        self.assertEqual(failures, [])

    def test_public_tree_boundary_rejects_private_repo_and_machine_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for index, value in enumerate((
                "plain prose btxchain/" + "private-fixture\n",
                "github.com/btxchain/" + "private-fixture\n",
                "www.github.com/btxchain/" + "private-fixture\n",
                "/opt/btxchain/" + "private-fixture\n",
                "/path/to/Documents/" + "btxchain/" + "private-fixture\n",
            )):
                with self.subTest(value=value):
                    failures = MODULE.check_public_tree_file(
                        self.write(root, f"repo-{index}.md", value))
                    self.assertTrue(any(
                        "repository name" in failure
                        for failure in failures
                    ))

            path = self.write(
                root,
                "machine-paths.md",
                "/Users/" + "fixture-operator/project/build\n"
                "/home/" + "fixture-operator/project/build\n"
                "C:\\Users\\" + "fixture-operator\\project\\build\n",
            )
            failures = MODULE.check_public_tree_file(path)
            self.assertTrue(any("macOS home path" in failure for failure in failures))
            self.assertTrue(any("Unix home path" in failure for failure in failures))
            self.assertTrue(any("Windows home path" in failure for failure in failures))

            credential_path = self.write(
                root,
                "credential-name.md",
                "/path/to/credentials/digitalocean_" + "api.key\n",
            )
            failures = MODULE.check_public_tree_file(credential_path)
            self.assertTrue(any(
                "provider credential filename" in failure
                for failure in failures
            ))

    def test_network_identity_and_path_names_fail(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = self.write(
                root,
                "network.md",
                "archive endpoint 192.0.2.55 validator.corp.example\n",
            )
            failures = MODULE.check_file(path)
            self.assertTrue(any("network address" in failure for failure in failures))
            self.assertTrue(any("non-allowlisted hostname" in failure for failure in failures))

            leaked_name = root / "validator.corp.example-report.md"
            leaked_name.write_text("sanitized contents\n", encoding="utf-8")
            failures = MODULE.check_public_tree_path(leaked_name)
            self.assertTrue(any("non-allowlisted hostname" in failure for failure in failures))

    def test_arbitrary_redacted_workspace_repo_slug_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.write(
                Path(directory),
                "release.md",
                "/path/to/Documents/" + "btxchain/" + "acme-prod/build\n",
            )
            failures = MODULE.check_public_tree_file(path)
            self.assertTrue(any("repository name" in failure for failure in failures))

    def test_reviewed_local_and_public_hosts_pass(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.write(
                Path(directory),
                "release.md",
                "127.0.0.1 ::1 github.com btxprice.com\n",
            )
            self.assertEqual(MODULE.check_network_identity(path.read_text(), path), [])

    def test_public_repo_query_and_path_forms_are_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.write(
                Path(directory),
                "release.md",
                "github.com/btxchain/btx?tab=readme\n"
                "https://github.com/btxchain/btx.git?tab=readme\n"
                "/opt/btxchain/btx/tree/main\n",
            )
            self.assertEqual(MODULE.check_public_tree_file(path), [])

    def test_placeholder_prefix_extensions_do_not_bypass_machine_path_rules(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for value in (
                "/Users/" + "you-private/project\n",
                "/Users/" + "${USER}suffix/project\n",
                "/home/" + "example-host/project\n",
                "/home/" + "user-private/project\n",
            ):
                failures = MODULE.check_public_tree_file(
                    self.write(root, "release.md", value))
                self.assertTrue(
                    any("home path" in failure for failure in failures),
                    value,
                )

    def test_default_publication_scope_covers_release_material(self) -> None:
        for relative in (
            "README.md",
            "ACTIVATION.md",
            ".github/ISSUE_TEMPLATE/bug_report.yml",
            "contrib/devtools/example.md",
            "doc/design/example.md",
            "doc/policy/example.md",
            "doc/release-manifests/example.json",
            "doc/release-notes.md",
            "docs/example.md",
            "formal-verification/example.md",
            "infra/example.md",
            "scripts/example.sh",
            "share/examples/example.conf",
            "test/util/example.py",
            "contrib/matmul-v4/derive-epoch-a-asert.py",
            "contrib/matmul-v4/measure-v3-regimes.cpp",
            "contrib/matmul-v4/verify-epoch-a-activation-gate.py",
        ):
            self.assertTrue(
                MODULE.is_btx_publication_path(REPO_ROOT / relative),
                relative,
            )
        self.assertFalse(
            MODULE.is_btx_publication_path(
                REPO_ROOT / "src/leveldb/README.md"))

    def test_public_tree_boundary_allows_documented_placeholders(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.write(
                Path(directory),
                "example.md",
                "/Users/you/project\n"
                "/Users/$USER/project\n"
                "/Users/${USER}/project\n"
                "/home/username/project\n"
                "/home/$USER/project\n"
                "/home/${USER}/project\n"
                "C:\\Users\\username\\project\n"
                "C:\\Users\\%USERNAME%\\project\n",
            )
            self.assertEqual(MODULE.check_public_tree_file(path), [])

    def test_complete_publishable_tree_is_clean(self) -> None:
        files = list(MODULE.tracked_public_files())
        self.assertGreater(len(files), 1_000)
        failures = [
            failure
            for path in files
            for failure in MODULE.check_public_tree_file(path)
        ]
        self.assertEqual(failures, [])


if __name__ == "__main__":
    unittest.main()
