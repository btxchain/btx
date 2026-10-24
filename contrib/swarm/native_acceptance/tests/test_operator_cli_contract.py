# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see COPYING.
"""Check wrapper/native parameter contracts without making any cloud requests."""

import contextlib
import importlib.machinery
import importlib.util
import io
from pathlib import Path
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[4]
LOADER = importlib.machinery.SourceFileLoader("btx_model_contract", str(ROOT / "contrib/modelnet/btx-model"))
SPEC = importlib.util.spec_from_loader(LOADER.name, LOADER)
CLI = importlib.util.module_from_spec(SPEC)
LOADER.exec_module(CLI)


class OperatorCliTests(unittest.TestCase):
    def test_wait_seconds_become_native_integer_milliseconds(self):
        with mock.patch.object(CLI, "_rpc_dev", return_value={"events": [], "cursor": "13"}) as rpc, mock.patch.object(CLI, "_emit_dev") as emit:
            CLI.cmd_events("test-only", ["--cursor", "12", "--wait", "1.25"])
        self.assertEqual(rpc.call_args_list[0].args[1], "getmodelevents")
        call = rpc.call_args_list[1]
        self.assertEqual(call.args[1], "waitformodelevent")
        self.assertEqual(call.args[2][0][0]["timeout_ms"], 1250)
        self.assertEqual(call.args[2][1], [12, 1250])
        self.assertEqual(emit.call_args.args[3]["next_cursor"], "13")

    def test_zero_wait_does_not_long_poll(self):
        with mock.patch.object(CLI, "_rpc_dev", return_value={"events": [], "cursor": "0"}) as rpc, mock.patch.object(CLI, "_emit_dev"):
            CLI.cmd_events("test-only", ["--wait", "0"])
        self.assertEqual(rpc.call_count, 1)

    def test_nonfinite_wait_refused_before_rpc(self):
        for value in ("nan", "inf", "-1", "86401"):
            with self.subTest(value=value), mock.patch.object(CLI, "_rpc_dev") as rpc, contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    CLI.cmd_events("test-only", ["--wait", value])
                rpc.assert_not_called()

    def test_https_selection_reaches_native_cloud_use_fake_false(self):
        with mock.patch.object(CLI, "_rpc_dev", return_value={}) as rpc, mock.patch.object(CLI, "_emit_dev"):
            CLI.cmd_cloud("test-only", ["add", "--endpoint", "https://example.invalid", "--bucket", "test", "--transport", "https"])
        self.assertEqual(rpc.call_args.args[1], "setcloudstorage")
        self.assertIs(rpc.call_args.args[2][0][0]["use_fake"], False)

    def test_existing_fake_cloud_default_is_explicit(self):
        with mock.patch.object(CLI, "_rpc_dev", return_value={}) as rpc, mock.patch.object(CLI, "_emit_dev"):
            CLI.cmd_cloud("test-only", ["add", "--endpoint", "https://example.invalid", "--bucket", "test"])
        self.assertIs(rpc.call_args.args[2][0][0]["use_fake"], True)

    def test_unknown_cloud_transport_refused_before_rpc(self):
        with mock.patch.object(CLI, "_rpc_dev") as rpc, contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                CLI.cmd_cloud("test-only", ["add", "--endpoint", "https://example.invalid", "--bucket", "test", "--transport", "automatic"])
            rpc.assert_not_called()

    def test_custom_profile_is_sent_with_its_overrides(self):
        with mock.patch.object(CLI, "_rpc_dev", return_value={"storage_arg": "1048576"}) as rpc, mock.patch.object(CLI, "_emit_dev") as emit:
            CLI.cmd_profile("test-only", ["set", "custom", '{"storage_bytes":1048576,"follow_peers":false}'])
        variants = rpc.call_args.args[2]
        self.assertEqual(len(variants), 1)
        self.assertEqual(variants[0][0]["storage_bytes"], 1048576)
        self.assertIs(variants[0][0]["follow_peers"], False)
        self.assertEqual(emit.call_args.args[3]["storage_bytes"], "1048576")


if __name__ == "__main__":
    unittest.main()
