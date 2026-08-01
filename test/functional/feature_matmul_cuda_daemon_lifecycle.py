#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Hardware-gated regression test for CUDA initialization across daemon fork modes.

This test intentionally uses the real CUDA backend and the production-shape RC
configuration.  It is opt-in because ordinary CI has no CUDA device.  A mock
backend cannot detect inherited CUDA contexts, handles, allocations, once_flags,
or qualification caches.

Canonical CUDA-host invocation (explicit config avoids multi-build auto-select):

  BTX_RUN_CUDA_DAEMON_LIFECYCLE_TESTS=1 \\
    build-cuda/test/functional/test_runner.py \\
    --configfile=build-cuda/test/config.ini \\
    feature_matmul_cuda_daemon_lifecycle.py
"""

import json
import os
import platform
import signal
import subprocess
import time
from pathlib import Path

from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.util import assert_equal, rpc_port

# Keep RC on the canonical regtest schedule (v4/BMX4C/DRLT default at 100).
# A lone earlier -regtestrcheight trips ValidateMatMulAsertParams.
RC_HEIGHT = 101


class MatMulCudaDaemonLifecycleTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 0
        self.setup_clean_chain = True

    def setup_network(self):
        pass

    def skip_test_if_missing_module(self):
        if platform.system() != "Linux":
            raise SkipTest("real CUDA daemon lifecycle test requires Linux")
        if os.environ.get("BTX_RUN_CUDA_DAEMON_LIFECYCLE_TESTS") != "1":
            raise SkipTest(
                "set BTX_RUN_CUDA_DAEMON_LIFECYCLE_TESTS=1 on a CUDA host"
            )

    def _cli(self, datadir, port, *args, timeout=180):
        command = [
            self.options.bitcoincli,
            "-regtest",
            f"-datadir={datadir}",
            f"-rpcport={port}",
            "-rpcuser=daemon_cuda_test",
            "-rpcpassword=daemon_cuda_test_password",
            "-rpcwait",
            f"-rpcwaittimeout={timeout}",
            *args,
        ]
        result = subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
            timeout=timeout + 15,
        )
        return result.stdout.strip()

    def _wait_rpc(self, datadir, port, process, timeout):
        """Wait for RPC, failing immediately if a foreground child exits."""
        deadline = time.monotonic() + timeout
        last_err = ""
        while time.monotonic() < deadline:
            if process is not None:
                exit_code = process.poll()
                if exit_code is not None:
                    console = datadir / "btxd.console.log"
                    debug = datadir / "regtest" / "debug.log"
                    chunks = [f"foreground btxd exited early with code {exit_code}"]
                    for label, path in (("console", console), ("debug.log", debug)):
                        if path.exists():
                            text = path.read_text(encoding="utf-8", errors="replace")
                            chunks.append(f"--- {label} (tail) ---\n{text[-4000:]}")
                    raise AssertionError("\n".join(chunks))
            try:
                return self._cli(datadir, port, "getmininginfo", timeout=5)
            except (subprocess.SubprocessError, OSError) as exc:
                last_err = str(exc)
                time.sleep(0.25)
        raise AssertionError(
            f"RPC not ready within {timeout}s for datadir={datadir}: {last_err}"
        )

    def _cuda_successes(self, info):
        runtime = info.get("backend_runtime") or {}
        if "cuda_successes" in runtime:
            return int(runtime["cuda_successes"])
        raise AssertionError(
            "getmininginfo.backend_runtime missing cuda_successes counter"
        )

    def _run_mode(self, mode, index):
        datadir = Path(self.options.tmpdir) / mode
        datadir.mkdir(parents=True)
        port = rpc_port(index)
        args = [
            self.options.bitcoind,
            "-regtest",
            f"-datadir={datadir}",
            f"-rpcport={port}",
            "-rpcuser=daemon_cuda_test",
            "-rpcpassword=daemon_cuda_test_password",
            "-server=1",
            "-listen=0",
            "-miningminoutboundpeers=0",
            "-miningminsyncedoutboundpeers=0",
            "-matmulvalidation=consensus",
            "-matmulrcexecution=strict-device",
            f"-regtestrcheight={RC_HEIGHT}",
            "-regtestrctoydims=0",
            "-regtestrcprofile=1",
            "-regtestmatmulv4dimension=4096",
            "-regtestmatmulv4maxdimension=4096",
        ]
        if mode == "daemon":
            args.append("-daemon")
        elif mode == "daemonwait":
            args.append("-daemonwait")

        env = dict(os.environ)
        env.update(
            BTX_MATMUL_BACKEND="cuda",
            BTX_MATMUL_V4_BACKEND="cuda",
            BTX_MATMUL_REQUIRE_BACKEND="cuda",
        )

        process = None
        timeout_factor = max(1.0, float(self.options.timeout_factor))
        startup_timeout = int(240 * timeout_factor)
        mining_timeout = int(300 * timeout_factor)
        console_log = datadir / "btxd.console.log"
        try:
            if mode == "foreground":
                console_fh = open(console_log, "w", encoding="utf-8")
                process = subprocess.Popen(
                    args,
                    env=env,
                    stdout=console_fh,
                    stderr=subprocess.STDOUT,
                )
                process._btx_console_fh = console_fh  # noqa: SLF001 — test-only
            else:
                subprocess.run(
                    args, env=env, check=True, timeout=startup_timeout
                )

            info = json.loads(self._wait_rpc(datadir, port, process, startup_timeout))
            br = info.get("backend_runtime") or {}
            if str(br.get("active_backend", "")).lower() != "cuda":
                raise AssertionError(
                    f"{mode}: active_backend is not cuda: {br.get('active_backend')}"
                )
            if not br.get("required_backend_satisfied", False):
                raise AssertionError(
                    f"{mode}: required CUDA backend not satisfied: "
                    f"{br.get('backend_requirement_reason')}"
                )

            rc = br["rc_exact_replay"]
            provider = rc["resolved_provider"]
            canary = rc["production_canary"]
            if "cuda" not in provider.lower():
                raise AssertionError(f"{mode}: non-CUDA RC provider: {provider}")
            if not canary.get("device_architecture", "").startswith("sm_"):
                raise AssertionError(f"{mode}: missing CUDA architecture identity")
            if int(canary.get("epoch_activation_height", -1)) != RC_HEIGHT:
                raise AssertionError(
                    f"{mode}: unexpected canary epoch_activation_height "
                    f"{canary.get('epoch_activation_height')}"
                )
            network = json.loads(self._cli(datadir, port, "getnetworkinfo"))
            services = network["localservicesnames"]
            if canary["outcome"] == "passed":
                if "MATMUL_CONSENSUS" not in services:
                    raise AssertionError(
                        f"{mode}: passed strict canary did not publish consensus service"
                    )
            elif "MATMUL_CONSENSUS" in services:
                raise AssertionError(
                    f"{mode}: fail-closed canary advertised consensus service"
                )
            if "MATMUL_ATTESTATION_ARCHIVE" in services:
                raise AssertionError(
                    f"{mode}: archive service advertised without a configured signer"
                )

            successes_before = self._cuda_successes(info)

            # Mine real legacy CUDA work after RC self-qualification/canary ran
            # in the final process. This is the shortest regression for stale
            # post-fork CUDA state and failed before the initialization fix.
            hashes = json.loads(
                self._cli(
                    datadir,
                    port,
                    "generatetodescriptor",
                    "1",
                    "raw(51)",
                    timeout=mining_timeout,
                )
            )
            assert_equal(len(hashes), 1)
            assert_equal(int(self._cli(datadir, port, "getblockcount")), 1)

            after = json.loads(self._cli(datadir, port, "getmininginfo"))
            after_br = after.get("backend_runtime") or {}
            successes_after = self._cuda_successes(after)
            if successes_after <= successes_before:
                raise AssertionError(
                    f"{mode}: cuda_successes did not increase after mining "
                    f"({successes_before} -> {successes_after})"
                )
            if str(after_br.get("active_backend", "")).lower() != "cuda":
                raise AssertionError(
                    f"{mode}: post-mine active_backend left cuda: "
                    f"{after_br.get('active_backend')}"
                )
            if not after_br.get("required_backend_satisfied", False):
                raise AssertionError(
                    f"{mode}: post-mine required CUDA backend unsatisfied"
                )
            after_rc = after_br["rc_exact_replay"]
            if "cuda" not in str(after_rc.get("resolved_provider", "")).lower():
                raise AssertionError(
                    f"{mode}: post-mine RC provider left CUDA path: "
                    f"{after_rc.get('resolved_provider')}"
                )

            log = (datadir / "regtest" / "debug.log").read_text(encoding="utf-8")
            forbidden = (
                "cudaSetDevice failed:initialization error",
                "required mining backend not satisfied",
                "CUDA backend fallback to CPU",
            )
            for marker in forbidden:
                if marker in log:
                    raise AssertionError(f"{mode}: observed forbidden CUDA lifecycle marker: {marker}")

            return {
                "provider": provider,
                "architecture": canary["device_architecture"],
                "driver": canary["driver_identity"],
                "runtime": canary["runtime_identity"],
                "canary": canary["outcome"],
                "services": services,
            }
        finally:
            try:
                self._cli(datadir, port, "stop", timeout=30)
            except (subprocess.SubprocessError, OSError):
                pass
            if process is not None:
                try:
                    process.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=10)
                console_fh = getattr(process, "_btx_console_fh", None)
                if console_fh is not None:
                    console_fh.close()
            else:
                # -daemon returns before the detached child exits. Do not reuse
                # its directory until the pid file disappears.
                deadline = time.monotonic() + 30
                pid = datadir / "regtest" / "btxd.pid"
                while pid.exists() and time.monotonic() < deadline:
                    time.sleep(0.1)
                if pid.exists():
                    # The PID belongs to this test's private datadir. Escalate
                    # cleanup so a failed mode cannot retain the GPU or taint
                    # the following foreground/daemon comparison.
                    try:
                        child_pid = int(pid.read_text(encoding="utf-8").strip())
                        cmdline = Path(f"/proc/{child_pid}/cmdline").read_bytes()
                        if (
                            Path(self.options.bitcoind).name.encode() not in cmdline
                            or str(datadir).encode() not in cmdline
                        ):
                            raise OSError("stale pid file did not identify this test daemon")
                        os.kill(child_pid, signal.SIGTERM)
                        deadline = time.monotonic() + 10
                        while pid.exists() and time.monotonic() < deadline:
                            time.sleep(0.1)
                        if pid.exists():
                            os.kill(child_pid, signal.SIGKILL)
                    except (OSError, ValueError):
                        pass

    def run_test(self):
        # Fail early if the selected binary cannot satisfy a required CUDA backend.
        bitcoind = Path(self.options.bitcoind)
        help_text = subprocess.run(
            [str(bitcoind), "-help-debug"],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        ).stdout
        if "matmulrcexecution" not in help_text:
            raise AssertionError(
                f"selected bitcoind lacks MatMul RC options: {bitcoind}"
            )

        observations = [
            self._run_mode("foreground", 0),
            self._run_mode("daemon", 1),
            self._run_mode("daemonwait", 2),
        ]
        expected = observations[0]
        for observed in observations[1:]:
            assert_equal(observed, expected)

        # The committed launch-candidate manifest is deliberately empty. Once
        # reviewed production goldens exist, the same final binary must rerun
        # this test with a passed canary before the separate two-daemon RC-boundary
        # campaign can be accepted as activation evidence.
        if os.environ.get("BTX_REQUIRE_CUDA_DAEMON_CANARY_PASS") == "1":
            assert_equal(expected["canary"], "passed")


if __name__ == "__main__":
    MatMulCudaDaemonLifecycleTest(__file__).main()
