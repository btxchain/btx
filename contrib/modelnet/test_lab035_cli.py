#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Drive contrib/modelnet/lab035 and check the local planner contract."""

from __future__ import annotations

import json
import subprocess
import unittest
from pathlib import Path

CLI = Path(__file__).resolve().parent / "lab035"

SUBCOMMANDS = (
    ["identity"],
    ["git", "--path", "repos/demo"],
    ["workspace", "--path", "workspaces/demo"],
    ["research", "--topic", "replay"],
    ["evidence", "--path", "evidence/demo.json"],
    ["model", "--model", "model-1"],
    ["agent", "--agent", "agent-1"],
    ["realm", "--realm", "realm-1"],
    ["promotion", "--promotion", "promo-1"],
    ["channel", "--channel", "chan-1"],
    ["rollout", "--rollout", "roll-1"],
    ["bundle", "--path", "bundles/demo"],
    ["migration", "--plan", "plan-1"],
    ["status"],
)

STATUS_FIELDS = (
    "source_commit",
    "snapshot",
    "signer",
    "coverage",
    "assurance",
    "policy",
    "disputes",
    "replicas",
    "runtime_generation",
)


def run_cli(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(CLI), *args],
        check=False,
        capture_output=True,
        text=True,
    )


class Lab035CliTest(unittest.TestCase):
    def test_each_subcommand_plans_without_spend(self) -> None:
        for args in SUBCOMMANDS:
            with self.subTest(args=args):
                result = run_cli([*args, "--json"])
                self.assertEqual(result.returncode, 0, result.stderr)
                payload = json.loads(result.stdout)
                self.assertEqual(payload["command"], args[0])
                self.assertIsInstance(payload["automatic_spend_atoms"], str)
                self.assertEqual(payload["automatic_spend_atoms"], "0")
                self.assertTrue(payload["effect"])
                self.assertTrue(payload["required_authority"])
                self.assertIsInstance(payload["contacts_peers"], bool)
                self.assertIs(payload["executed_peer_contact"], False)
                self.assertIs(payload["no_spend"], True)
                self.assertIs(payload["planned"], True)
                self.assertIn("path_safety", payload["checks"])
                self.assertIn("no_spend", payload["checks"])

    def test_json_flag_before_command(self) -> None:
        result = run_cli(["--json", "identity"])
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["command"], "identity")
        self.assertEqual(payload["automatic_spend_atoms"], "0")

    def test_identity_does_not_return_a_secret(self) -> None:
        result = run_cli(["identity", "--json"])
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertIs(payload["secret_returned"], False)
        self.assertNotIn("secret", payload)
        self.assertNotIn("private_key", payload)
        self.assertNotIn("seed", payload)
        self.assertIn("no_secret_export", payload["checks"])

    def test_unknown_subcommand_exits_nonzero(self) -> None:
        result = run_cli(["not-a-command", "--json"])
        self.assertNotEqual(result.returncode, 0)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["command"], "not-a-command")
        self.assertEqual(payload["automatic_spend_atoms"], "0")
        self.assertEqual(payload["error"], "BTX035_ROUTE")
        self.assertNotIn("{", result.stderr)

    def test_missing_command_exits_nonzero(self) -> None:
        result = run_cli(["--json"])
        self.assertNotEqual(result.returncode, 0)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["automatic_spend_atoms"], "0")
        self.assertEqual(payload["error"], "BTX035_ROUTE")

    def test_missing_required_flag_is_schema(self) -> None:
        for args in (["git", "--json"], ["bundle", "--json"], ["migration", "--json"], ["model", "--json"]):
            with self.subTest(args=args):
                result = run_cli(args)
                self.assertNotEqual(result.returncode, 0)
                payload = json.loads(result.stdout)
                self.assertEqual(payload["command"], args[0])
                self.assertEqual(payload["automatic_spend_atoms"], "0")
                self.assertEqual(payload["error"], "BTX035_SCHEMA")
                self.assertIn("missing", payload)

    def test_unsafe_paths_are_rejected(self) -> None:
        cases = (
            ["bundle", "--path", "../secret", "--json"],
            ["bundle", "--path", "/bin/sh", "--json"],
            ["git", "--path", "repos/demo;rm", "--json"],
            ["workspace", "--path", "/tmp/../../etc/passwd", "--json"],
            ["evidence", "--path", "/rpc/export", "--json"],
        )
        for args in cases:
            with self.subTest(args=args):
                result = run_cli(args)
                self.assertNotEqual(result.returncode, 0)
                payload = json.loads(result.stdout)
                self.assertEqual(payload["automatic_spend_atoms"], "0")
                self.assertEqual(payload["error"], "BTX035_PATH_UNSAFE")
                self.assertEqual(payload["path_safety"], "rejected")

    def test_spend_flags_do_not_spend(self) -> None:
        cases = (
            ["identity", "--json", "--spend"],
            ["model", "--model", "model-1", "--json", "--automatic-spend-atoms", "5"],
            ["realm", "--realm", "realm-1", "--json", "sendtoaddress"],
        )
        for args in cases:
            with self.subTest(args=args):
                result = run_cli(args)
                self.assertNotEqual(result.returncode, 0)
                payload = json.loads(result.stdout)
                self.assertEqual(payload["automatic_spend_atoms"], "0")
                self.assertIsInstance(payload["automatic_spend_atoms"], str)
                self.assertEqual(payload["error"], "BTX035_SCOPE_DENIED")
                self.assertIs(payload["executed_peer_contact"], False)

    def test_status_reports_gap_and_has_no_trusted_flag(self) -> None:
        result = run_cli(["status", "--json"])
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        for field in STATUS_FIELDS:
            self.assertIn(field, payload)
            self.assertIsInstance(payload[field], str)
        self.assertEqual(payload["coverage"], "gap")
        self.assertNotIn("trusted", payload)
        self.assertNotIn('"trusted": true', result.stdout)
        self.assertNotIn('"trusted":true', result.stdout)

    def test_status_keeps_explicit_coverage_and_assurance(self) -> None:
        result = run_cli(
            [
                "status",
                "--json",
                "--source-commit",
                "abc123",
                "--snapshot",
                "snap-1",
                "--signer",
                "signer-1",
                "--coverage",
                "partial",
                "--assurance",
                "DELEGATED_POLICY_ATTESTED",
                "--policy",
                "realm-policy-1",
                "--disputes",
                "dispute-1",
                "--replicas",
                "2",
                "--runtime-generation",
                "gen-9",
            ]
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["source_commit"], "abc123")
        self.assertEqual(payload["snapshot"], "snap-1")
        self.assertEqual(payload["signer"], "signer-1")
        self.assertEqual(payload["coverage"], "partial")
        self.assertEqual(payload["assurance"], "DELEGATED_POLICY_ATTESTED")
        self.assertEqual(payload["policy"], "realm-policy-1")
        self.assertEqual(payload["disputes"], "dispute-1")
        self.assertEqual(payload["replicas"], "2")
        self.assertEqual(payload["runtime_generation"], "gen-9")
        self.assertNotEqual(payload["assurance"], "trusted")
        self.assertNotIn("trusted", payload)

    def test_blank_coverage_is_a_visible_gap(self) -> None:
        result = run_cli(["status", "--json", "--coverage", "   "])
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["coverage"], "gap")
        self.assertIn("coverage", payload)


if __name__ == "__main__":
    unittest.main()
