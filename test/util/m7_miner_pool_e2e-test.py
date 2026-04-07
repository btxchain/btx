#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Unit tests for scripts/m7_miner_pool_e2e.py helper behavior."""

import importlib.util
import io
import json
import os
import pathlib
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch


ROOT_DIR = pathlib.Path(__file__).resolve().parents[2]
SCRIPT_PATH = ROOT_DIR / "scripts" / "m7_miner_pool_e2e.py"


def load_module():
    spec = importlib.util.spec_from_file_location("m7_miner_pool_e2e", SCRIPT_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load module from {SCRIPT_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


m7 = load_module()


class M7MinerPoolE2ETest(unittest.TestCase):
    def test_resolve_template_only_regtest_respects_flag(self):
        self.assertTrue(m7.resolve_template_only("regtest", True))
        self.assertFalse(m7.resolve_template_only("regtest", False))

    def test_resolve_template_only_testnet_forces_true(self):
        self.assertTrue(m7.resolve_template_only("testnet", True))
        self.assertTrue(m7.resolve_template_only("testnet", False))

    def test_indicates_missing_method_unknown_command(self):
        self.assertTrue(m7.indicates_missing_method("help: unknown command: createwallet"))

    def test_indicates_missing_method_method_not_found(self):
        self.assertTrue(m7.indicates_missing_method("error code: -32601\nMethod not found"))

    def test_rpc_method_available_true_when_help_lists_method(self):
        with patch.object(m7, "run_cli", return_value="createwallet: ..."):
            self.assertTrue(m7.rpc_method_available(pathlib.Path("cli"), pathlib.Path("data"), "regtest", "createwallet"))

    def test_rpc_method_available_false_when_help_returns_unknown_command(self):
        with patch.object(m7, "run_cli", return_value="help: unknown command: createwallet"):
            self.assertFalse(m7.rpc_method_available(pathlib.Path("cli"), pathlib.Path("data"), "regtest", "createwallet"))

    def test_rpc_method_available_false_when_rpc_raises_method_not_found(self):
        err = subprocess.CalledProcessError(
            returncode=1,
            cmd=["btx-cli", "help", "createwallet"],
            output="",
            stderr="error code: -32601\nerror message:\nMethod not found\n",
        )
        with patch.object(m7, "run_cli", side_effect=err):
            self.assertFalse(m7.rpc_method_available(pathlib.Path("cli"), pathlib.Path("data"), "regtest", "createwallet"))

    def test_rpc_method_available_reraises_unrelated_rpc_errors(self):
        err = subprocess.CalledProcessError(
            returncode=1,
            cmd=["btx-cli", "help", "createwallet"],
            output="",
            stderr="error: temporary rpc transport failure",
        )
        with patch.object(m7, "run_cli", side_effect=err):
            with self.assertRaises(subprocess.CalledProcessError):
                m7.rpc_method_available(pathlib.Path("cli"), pathlib.Path("data"), "regtest", "createwallet")

    def test_run_cli_uses_env_rpc_port_when_not_provided(self):
        with patch.dict(os.environ, {"BTX_RPC_PORT": "19444"}, clear=False):
            with patch.object(m7.subprocess, "run") as mock_run:
                mock_run.return_value = subprocess.CompletedProcess(
                    args=["btx-cli"], returncode=0, stdout="1\n", stderr=""
                )
                output = m7.run_cli(
                    pathlib.Path("/tmp/btx-cli"),
                    pathlib.Path("/tmp/datadir"),
                    "regtest",
                    ["getblockcount"],
                )

        self.assertEqual(output, "1")
        cmd = mock_run.call_args.args[0]
        self.assertIn("-rpcport=19444", cmd)
        timeout_args = [arg for arg in cmd if arg.startswith("-rpcclienttimeout=")]
        self.assertEqual(len(timeout_args), 1, cmd)
        timeout_value = int(timeout_args[0].split("=", 1)[1])
        self.assertGreater(timeout_value, 0)

    def test_run_cli_honors_rpc_client_timeout_env_override(self):
        with patch.dict(
            os.environ,
            {"BTX_RPC_PORT": "19444", "BTX_M7_RPC_CLIENT_TIMEOUT_SECONDS": "9"},
            clear=False,
        ):
            with patch.object(m7.subprocess, "run") as mock_run:
                mock_run.return_value = subprocess.CompletedProcess(
                    args=["btx-cli"], returncode=0, stdout="1\n", stderr=""
                )
                m7.run_cli(
                    pathlib.Path("/tmp/btx-cli"),
                    pathlib.Path("/tmp/datadir"),
                    "regtest",
                    ["getblockcount"],
                )

        cmd = mock_run.call_args.args[0]
        self.assertIn("-rpcclienttimeout=9", cmd)

    def test_wait_for_rpc_fails_if_daemon_exits_early(self):
        class DeadDaemon:
            @staticmethod
            def poll():
                return 1

        with patch.object(m7, "run_cli", side_effect=subprocess.CalledProcessError(1, ["btx-cli"])):
            with self.assertRaisesRegex(RuntimeError, "exited before RPC became available"):
                m7.wait_for_rpc(pathlib.Path("cli"), pathlib.Path("data"), "regtest", daemon=DeadDaemon())

    def test_wait_for_rpc_eventually_succeeds_after_retries(self):
        attempts = [
            subprocess.CalledProcessError(1, ["btx-cli"]),
            subprocess.CalledProcessError(1, ["btx-cli"]),
            "0",
        ]
        with patch.object(m7, "run_cli", side_effect=attempts):
            with patch.object(m7.time, "sleep", return_value=None):
                m7.wait_for_rpc(pathlib.Path("cli"), pathlib.Path("data"), "regtest")

    def test_build_sendtoaddress_args_uses_explicit_fee_rate(self):
        args = m7.build_sendtoaddress_args("btxrt1qexampledestination")
        self.assertEqual(args[0], "sendtoaddress")
        self.assertIn("fee_rate=30", args)
        self.assertFalse(any(arg.startswith("conf_target=") for arg in args))
        self.assertFalse(any(arg.startswith("estimate_mode=") for arg in args))

    def test_query_backend_info_returns_fallback_when_binary_missing(self):
        info = m7.query_backend_info(pathlib.Path("/nonexistent/backend-info"), "metal")
        self.assertEqual(info["requested_input"], "metal")
        self.assertEqual(info["active_backend"], "cpu")
        self.assertIn("fallback_to_cpu", info["selection_reason"])

    def test_query_backend_info_parses_json_payload(self):
        payload = {
            "requested_input": "metal",
            "requested_known": True,
            "requested_backend": "metal",
            "active_backend": "metal",
            "selection_reason": "requested_backend_available",
            "capabilities": {},
        }
        with patch.object(pathlib.Path, "is_file", return_value=True):
            with patch.object(
                m7.subprocess,
                "run",
                return_value=subprocess.CompletedProcess(
                    args=["btx-matmul-backend-info"],
                    returncode=0,
                    stdout=json.dumps(payload),
                    stderr="",
                ),
            ):
                info = m7.query_backend_info(pathlib.Path("/tmp/btx-matmul-backend-info"), "metal")
        self.assertEqual(info, payload)

    def test_main_regtest_wallet_uses_named_sendtoaddress(self):
        with tempfile.TemporaryDirectory() as tmp:
            build = pathlib.Path(tmp) / "build"
            args = type(
                "Args",
                (),
                {
                    "build_dir": str(build),
                    "artifact": None,
                    "chain": "regtest",
                    "template_only": False,
                    "backend": "metal",
                },
            )()

            class FakeDaemon:
                @staticmethod
                def poll():
                    return None

                @staticmethod
                def wait(timeout=None):
                    return 0

                @staticmethod
                def kill():
                    return None

            mempool_calls = {"count": 0}

            def fake_run_cli(_cli, _datadir, _chain, cli_args, **kwargs):
                cmd = cli_args[0]
                if cmd == "createwallet":
                    return '{"name":"m7_pool"}'
                if cmd == "getnewaddress" and cli_args[1] == "pool-payout":
                    return "btxrt1qpoolpayoutaddress0000000000000000000000000000000000"
                if cmd == "generatetoaddress":
                    return '["00"]'
                if cmd == "getnewaddress" and cli_args[1] == "pool-target":
                    return "btxrt1qpooltargetaddress0000000000000000000000000000000000"
                if cmd == "sendtoaddress":
                    self.assertTrue(kwargs.get("named"))
                    self.assertIn("fee_rate=30", cli_args)
                    self.assertFalse(any(arg.startswith("conf_target=") for arg in cli_args))
                    self.assertFalse(any(arg.startswith("estimate_mode=") for arg in cli_args))
                    return "txid1"
                if cmd == "getrawmempool":
                    mempool_calls["count"] += 1
                    return '["txid1"]' if mempool_calls["count"] == 1 else "[]"
                if cmd == "getmempoolentry":
                    return (
                        '{"wtxid":"wtxid1","vsize":141,"weight":564,'
                        '"fees":{"base":0.00010000},"bip125-replaceable":true,'
                        '"descendantcount":1}'
                    )
                if cmd == "gettransaction":
                    return (
                        '{"amount":-1.00000000,"fee":-0.00010000,'
                        '"confirmations":0,"details":[],"hex":"00"}'
                    )
                if cmd == "getblocktemplate":
                    return (
                        '{"height":111,"previousblockhash":"00","bits":"1d00ffff",'
                        '"target":"00","noncerange":"0000000000000000ffffffffffffffff",'
                        '"coinbasevalue":5000000000}'
                    )
                if cmd == "generateblock":
                    return '{"hash":"abcd","hex":"00"}'
                if cmd == "submitblock":
                    return "null"
                if cmd == "getblockheader" and len(cli_args) >= 3 and cli_args[2] == "false":
                    return (
                        "01000000"
                        + ("00" * 32)
                        + ("00" * 32)
                        + "00000000"
                        + "00000000"
                        + "0200000000000000"
                        + ("00" * 32)
                        + "4000"
                        + ("00" * 32)
                        + ("00" * 32)
                    )
                if cmd == "getblockheader":
                    return '{"nonce":1}'
                if cmd == "getblock":
                    return '{"height":111,"tx":["txid1"]}'
                if cmd == "getbestblockhash":
                    return "abcd"
                if cmd == "stop":
                    return "stopped"
                raise AssertionError(f"unexpected CLI command: {cmd}")

            with patch.object(m7, "parse_args", return_value=args):
                with patch.object(m7, "ensure_executable", side_effect=lambda p: p):
                    with patch.object(m7, "find_free_port", return_value=19444):
                        with patch.object(m7.subprocess, "Popen", return_value=FakeDaemon()):
                            with patch.object(m7, "wait_for_rpc", return_value=None):
                                with patch.object(m7, "rpc_method_available", return_value=True):
                                    with patch.object(m7, "run_cli", side_effect=fake_run_cli):
                                        rc = m7.main()

            self.assertEqual(rc, 0)

    def test_main_template_only_testnet_does_not_require_submitted_block(self):
        with tempfile.TemporaryDirectory() as tmp:
            build = pathlib.Path(tmp) / "build"
            args = type(
                "Args",
                (),
                {
                    "build_dir": str(build),
                    "artifact": None,
                    "chain": "testnet",
                    "template_only": False,
                    "backend": "cpu",
                },
            )()

            class FakeDaemon:
                @staticmethod
                def poll():
                    return None

                @staticmethod
                def wait(timeout=None):
                    return 0

                @staticmethod
                def kill():
                    return None

            def fake_run_cli(_cli, _datadir, _chain, args, **_kwargs):
                cmd = args[0]
                if cmd == "getblocktemplate":
                    return (
                        '{"height":1,"previousblockhash":"00","bits":"1d00ffff",'
                        '"target":"00","noncerange":"0000000000000000ffffffffffffffff",'
                        '"coinbasevalue":5000000000}'
                    )
                if cmd == "stop":
                    return "stopped"
                raise AssertionError(f"unexpected CLI command: {cmd}")

            out = io.StringIO()
            with patch.object(m7, "parse_args", return_value=args):
                with patch.object(m7, "ensure_executable", side_effect=lambda p: p):
                    with patch.object(m7, "find_free_port", return_value=19444):
                        with patch.object(m7.subprocess, "Popen", return_value=FakeDaemon()):
                            with patch.object(m7, "wait_for_rpc", return_value=None):
                                with patch.object(m7, "rpc_method_available", return_value=False):
                                    with patch.object(m7, "run_cli", side_effect=fake_run_cli):
                                        with redirect_stdout(out):
                                            rc = m7.main()

            self.assertEqual(rc, 0)
            output = out.getvalue()
            self.assertIn("Template-only mode", output)
            self.assertNotIn("Accepted block", output)


if __name__ == "__main__":
    unittest.main()
