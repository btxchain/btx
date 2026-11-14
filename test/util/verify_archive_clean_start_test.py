#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Tests for scripts/release/verify_archive_clean_start.py.

The start script is run with the host `sh` against a fake archive whose btxd
and btx-cli are small shell scripts, so each step and each failure code is
exercised without a container.
"""

from __future__ import annotations

import importlib.util
import io
import os
import pathlib
import stat
import subprocess
import tarfile
import tempfile
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "release" / "verify_archive_clean_start.py"

spec = importlib.util.spec_from_file_location("verify_archive_clean_start", SCRIPT)
assert spec is not None and spec.loader is not None
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

FAKE_BTXD = """#!/bin/sh
case "$1" in
  -version) {version_action} ;;
esac
for arg in "$@"; do
  case "$arg" in
    -datadir=*) dir="${{arg#-datadir=}}" ;;
  esac
done
{start_action}
"""

FAKE_CLI = """#!/bin/sh
for arg in "$@"; do
  case "$arg" in
    -datadir=*) dir="${{arg#-datadir=}}" ;;
  esac
done
cmd=""
for arg in "$@"; do
  case "$arg" in
    -*) ;;
    *) cmd="$arg" ;;
  esac
done
echo "$cmd" >> "$dir/calls"
case "$cmd" in
  getblockchaininfo) [ -e "$dir/up" ] && echo '{{"chain": "{chain}"}}' && exit 0; exit 1 ;;
  getblockcount) [ -e "$dir/up" ] && echo 0 && exit 0; exit 1 ;;
  stop) {stop_action} ;;
esac
"""


def make_archive(directory: pathlib.Path, *, version_action: str = 'echo "BTX daemon version v0.0.0"; exit 0',
                 start_action: str = 'touch "$dir/up"; echo "BTX node starting"; exit 0',
                 chain: str = "regtest", stop_action: str = 'rm -f "$dir/up"; exit 0') -> pathlib.Path:
    files = {
        "btx-0.0.0/bin/btxd": FAKE_BTXD.format(version_action=version_action, start_action=start_action),
        "btx-0.0.0/bin/btx-cli": FAKE_CLI.format(chain=chain, stop_action=stop_action),
    }
    archive = directory / "btx-0.0.0-x86_64-linux-gnu.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        for name, text in files.items():
            data = text.encode()
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH
            tar.addfile(info, io.BytesIO(data))
    return archive


def run_start_script(archive: pathlib.Path, work: pathlib.Path, **env: str) -> subprocess.CompletedProcess[str]:
    full_env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "BTX_GATE_ARCHIVE": str(archive),
        "BTX_GATE_PREFIX": str(work / "prefix"),
        "BTX_GATE_DATADIR": str(work / "datadir"),
        "BTX_GATE_WAIT": "3",
        "BTX_GATE_STOP_WAIT": "3",
    }
    full_env.update(env)
    return subprocess.run(["sh", "-c", gate.START_SCRIPT], env=full_env, capture_output=True, text=True, check=False)


class StartScriptTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.work = pathlib.Path(self._tmp.name)

    def test_passes_when_the_node_starts_answers_and_stops(self) -> None:
        result = run_start_script(make_archive(self.work), self.work)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("gate-ok", result.stdout)

    def test_version_failure_reports_the_loader_message(self) -> None:
        message = "BTX btxd is missing runtime libraries: libpython3.12.so.1.0"
        archive = make_archive(self.work, version_action=f'echo "{message}"; exit 127')
        result = run_start_script(archive, self.work)
        self.assertEqual(result.returncode, 22)
        self.assertIn("step=-version exit=127", result.stdout)
        self.assertIn("libpython3.12.so.1.0", result.stdout)

    def test_daemon_start_failure(self) -> None:
        archive = make_archive(self.work, start_action='echo "init failed"; exit 1')
        result = run_start_script(archive, self.work)
        self.assertEqual(result.returncode, 23)
        self.assertIn("init failed", result.stdout)

    def test_no_answer_within_the_wait(self) -> None:
        archive = make_archive(self.work, start_action="exit 0")
        result = run_start_script(archive, self.work)
        self.assertEqual(result.returncode, 24)
        self.assertIn("step=getblockchaininfo", result.stdout)

    def test_a_node_on_another_chain_does_not_pass(self) -> None:
        result = run_start_script(make_archive(self.work, chain="main"), self.work)
        self.assertEqual(result.returncode, 24)

    def test_a_node_that_does_not_stop_fails(self) -> None:
        result = run_start_script(make_archive(self.work, stop_action="exit 0"), self.work)
        self.assertEqual(result.returncode, 25)
        self.assertIn("step=stop", result.stdout)

    def test_extra_btxd_arguments_are_passed(self) -> None:
        record = self.work / "args.txt"
        archive = make_archive(self.work, start_action=f'echo "$@" > {record}; touch "$dir/up"; exit 0')
        result = run_start_script(archive, self.work, BTX_GATE_ARGS="-swapnet=0 -foo=1", BTX_GATE_RPCPORT="19001")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        arguments = record.read_text(encoding="utf-8").split()
        for expected in ("-regtest=1", "-autoupdate=0", "-swapnet=0", "-foo=1", "-rpcport=19001", "-port=19002", "-daemon"):
            self.assertIn(expected, arguments)

    def test_unwritable_prefix_fails_at_mkdir(self) -> None:
        result = run_start_script(make_archive(self.work), self.work, BTX_GATE_PREFIX="/dev/null/btx")
        self.assertEqual(result.returncode, 20)
        self.assertIn("step=mkdir", result.stdout)

    def test_a_node_that_did_not_answer_is_stopped_before_the_script_leaves(self) -> None:
        archive = make_archive(self.work, start_action="exit 0")
        result = run_start_script(archive, self.work)
        self.assertEqual(result.returncode, 24)
        self.assertIn("stop", (self.work / "datadir" / "calls").read_text(encoding="utf-8").split())

    def test_a_node_that_ignores_stop_is_signalled_before_the_script_leaves(self) -> None:
        # A detached process stands in for btxd -daemon; its pid file is regtest/btxd.pid.
        action = ('mkdir -p "$dir/regtest"; sleep 300 > /dev/null 2>&1 & echo $! > "$dir/regtest/btxd.pid"; exit 0')
        result = run_start_script(make_archive(self.work, start_action=action, stop_action="exit 0"), self.work)
        self.assertEqual(result.returncode, 24)
        pid = int((self.work / "datadir" / "regtest" / "btxd.pid").read_text(encoding="utf-8"))
        end = time.monotonic() + 5
        while time.monotonic() < end:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                break
            time.sleep(0.1)
        else:
            os.kill(pid, 9)
            self.fail("the start script left the node running")

    def test_a_failed_start_names_the_swapnet_error(self) -> None:
        action = ('mkdir -p "$dir/regtest"; printf "%s\\n" "SwapNet: startup failed (SwapNet Python initialization failed). '
                  'No funds were authorized by startup." l1 l2 l3 l4 l5 l6 l7 "Shutdown: done" > "$dir/regtest/debug.log"; exit 0')
        result = run_start_script(make_archive(self.work, start_action=action), self.work)
        self.assertEqual(result.returncode, 24)
        self.assertIn("SwapNet: startup failed (SwapNet Python initialization failed)", result.stdout)

    def test_a_daemon_that_already_exited_does_not_wait_out_the_timeout(self) -> None:
        action = 'mkdir -p "$dir/regtest"; echo "Shutdown: done" > "$dir/regtest/debug.log"; exit 0'
        archive = make_archive(self.work, start_action=action)
        started = time.monotonic()
        result = run_start_script(archive, self.work, BTX_GATE_WAIT="60")
        self.assertEqual(result.returncode, 24)
        self.assertLess(time.monotonic() - started, 20)
        self.assertIn("Shutdown: done", result.stdout)

    def test_a_corrupt_archive_fails_at_extract(self) -> None:
        bad = self.work / "bad.tar.gz"
        bad.write_bytes(b"not a tarball")
        result = run_start_script(bad, self.work)
        self.assertEqual(result.returncode, 21)


class CommandTest(unittest.TestCase):
    def test_chroot_command_uses_a_clean_env(self) -> None:
        env = gate.script_env("/tmp/a.tar.gz", 18943, [])
        command = gate.chroot_command("/srv/noble", env)
        self.assertEqual(command[:4], ["chroot", "/srv/noble", "/usr/bin/env", "-i"])
        self.assertIn("BTX_GATE_ARCHIVE=/tmp/a.tar.gz", command)
        self.assertTrue(any(part.startswith("PATH=") for part in command))
        self.assertIn(f"HOME={env['BTX_GATE_DATADIR']}/home", command)
        self.assertEqual(sum(part.startswith("HOME=") for part in command), 1)

    def test_proot_command_binds_proc_dev_sys(self) -> None:
        env = gate.script_env("/tmp/a.tar.gz", 18943, [])
        command = gate.proot_command("/srv/noble", env)
        self.assertEqual(command[:3], ["proot", "-r", "/srv/noble"])
        for path in ("/proc", "/dev", "/sys"):
            self.assertEqual(command[command.index(path) - 1], "-b")
        self.assertEqual(command[command.index("/usr/bin/env") + 1], "-i")
        self.assertEqual(command[-1], gate.START_SCRIPT)
        self.assertEqual(gate.stop_command("proot", "/srv/noble", env), gate.proot_command("/srv/noble", env, gate.STOP_SCRIPT))
        self.assertEqual(gate.stop_command("chroot", "/srv/noble", env), gate.chroot_command("/srv/noble", env, gate.STOP_SCRIPT))


class RootfsTest(unittest.TestCase):
    """A root filesystem that cannot give a true result is refused, not run."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = pathlib.Path(self._tmp.name)

    def test_chroot_without_proc_is_refused(self) -> None:
        with mock.patch.object(gate.os, "geteuid", return_value=0):
            problem = gate.rootfs_problem("chroot", str(self.root))
        self.assertIsNotNone(problem)
        self.assertIn("/proc is not mounted", problem)
        self.assertIn("$ORIGIN", problem)

    def test_chroot_with_proc_and_root_is_accepted(self) -> None:
        (self.root / "proc" / "self").mkdir(parents=True)
        with mock.patch.object(gate.os, "geteuid", return_value=0):
            self.assertIsNone(gate.rootfs_problem("chroot", str(self.root)))

    def test_chroot_needs_root(self) -> None:
        (self.root / "proc" / "self").mkdir(parents=True)
        with mock.patch.object(gate.os, "geteuid", return_value=1000):
            self.assertEqual(gate.rootfs_problem("chroot", str(self.root)), "the chroot engine needs root")

    def test_a_proot_that_cannot_see_files_is_refused(self) -> None:
        (self.root / "tmp").mkdir()
        seen: list[str] = []

        def blind(command: list[str], **_options: object) -> subprocess.CompletedProcess[str]:
            marker = self.root / command[-1].split()[2].lstrip("/")
            seen.append(marker.read_text(encoding="ascii"))
            self.assertTrue(os.access(marker, os.X_OK))
            return subprocess.CompletedProcess(command, 1, stdout="", stderr="sh: 1: /tmp/x: not found\n")

        with mock.patch.object(gate.subprocess, "run", side_effect=blind):
            problem = gate.rootfs_problem("proot", str(self.root))
        self.assertIn("cannot see files", problem)
        self.assertEqual(seen, [gate.PROBE_TEXT])
        self.assertEqual(list((self.root / "tmp").iterdir()), [])

    def test_a_proot_that_sees_files_is_accepted(self) -> None:
        (self.root / "tmp").mkdir()
        seeing = subprocess.CompletedProcess([], 0, stdout="proot-sees-files\n", stderr="")
        with mock.patch.object(gate.subprocess, "run", return_value=seeing):
            self.assertIsNone(gate.rootfs_problem("proot", str(self.root)))
        self.assertEqual(list((self.root / "tmp").iterdir()), [])

    def test_the_probe_file_runs_with_sh(self) -> None:
        probe = self.root / "probe"
        probe.write_text(gate.PROBE_TEXT, encoding="ascii")
        probe.chmod(0o755)
        self.assertEqual(subprocess.run([str(probe)], capture_output=True, text=True, check=True).stdout, "proot-sees-files\n")

    def test_a_refused_root_is_a_failure_without_running_the_start(self) -> None:
        archive = make_archive(self.root)
        with mock.patch.object(gate.os, "geteuid", return_value=0), mock.patch.object(gate.subprocess, "run") as run:
            passed, output = gate.run_image("chroot", str(self.root), archive, 18943, [], 30)
        self.assertFalse(passed)
        self.assertIn("/proc is not mounted", output)
        run.assert_not_called()

    def test_auto_prefers_proot(self) -> None:
        with mock.patch.object(gate.shutil, "which", return_value="/usr/local/bin/proot"):
            self.assertEqual(gate.pick_engine("auto"), "proot")
        with mock.patch.object(gate.shutil, "which", return_value=None):
            self.assertEqual(gate.pick_engine("auto"), "chroot")
            self.assertIsNone(gate.pick_engine("proot"))

    def test_an_archive_already_in_the_root_survives_the_run(self) -> None:
        (self.root / "tmp").mkdir()
        archive = make_archive(self.root / "tmp")
        before = archive.read_bytes()
        done = subprocess.CompletedProcess([], 0, stdout="gate-ok\n", stderr="")
        with mock.patch.object(gate, "rootfs_problem", return_value=None), \
                mock.patch.object(gate.subprocess, "run", return_value=done) as run:
            passed, _ = gate.run_image("proot", str(self.root), archive, 18943, [], 30)
        self.assertTrue(passed)
        self.assertEqual(archive.read_bytes(), before)
        self.assertEqual(sorted(p.name for p in (self.root / "tmp").iterdir()), [archive.name])
        archive_arg = next(a for a in run.call_args[0][0] if a.startswith("BTX_GATE_ARCHIVE="))
        self.assertNotEqual(archive_arg, f"BTX_GATE_ARCHIVE=/tmp/{archive.name}")

    def test_a_probe_that_hangs_is_a_refusal(self) -> None:
        (self.root / "tmp").mkdir()
        with mock.patch.object(gate.subprocess, "run", side_effect=subprocess.TimeoutExpired(["proot"], 60)):
            problem = gate.rootfs_problem("proot", str(self.root))
        self.assertIn("within 60s", problem)
        self.assertEqual(list((self.root / "tmp").iterdir()), [])


class TimeoutTest(unittest.TestCase):
    """--timeout kills the start script, not the daemon it forked; the node must still be stopped."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.work = pathlib.Path(self._tmp.name)

    @staticmethod
    def alive(pid: int) -> bool:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        return True

    def fake_node(self) -> tuple[int, dict[str, str]]:
        """A detached process (like btxd -daemon) with a pid file, and a btx-cli whose `stop` ends it."""
        prefix, datadir = self.work / "prefix", self.work / "datadir"
        (prefix / "bin").mkdir(parents=True)
        (datadir / "regtest").mkdir(parents=True)
        started = subprocess.run(["sh", "-c", "sleep 300 > /dev/null 2>&1 & echo $!"], capture_output=True, text=True, check=True)
        pid = int(started.stdout)
        self.addCleanup(lambda: self.alive(pid) and os.kill(pid, 9))
        (datadir / "regtest" / "btxd.pid").write_text(f"{pid}\n", encoding="utf-8")
        cli = prefix / "bin" / "btx-cli"
        cli.write_text(f'#!/bin/sh\ncase "$*" in *stop*) kill {pid} ;; esac\n', encoding="utf-8")
        cli.chmod(0o755)
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "BTX_GATE_PREFIX": str(prefix),
               "BTX_GATE_DATADIR": str(datadir), "BTX_GATE_STOP_WAIT": "3"}
        return pid, env

    def gone_within(self, pid: int, seconds: float) -> bool:
        end = time.monotonic() + seconds
        while self.alive(pid) and time.monotonic() < end:
            time.sleep(0.1)
        return not self.alive(pid)

    def test_stop_script_stops_a_node_left_running(self) -> None:
        pid, env = self.fake_node()
        result = subprocess.run(["sh", "-c", gate.STOP_SCRIPT], env=env, capture_output=True, text=True, check=False)
        self.assertTrue(self.gone_within(pid, 5))
        self.assertIn(f"stopped pid={pid}", result.stdout)

    def test_stop_script_signals_a_node_that_ignores_stop(self) -> None:
        pid, env = self.fake_node()
        cli = pathlib.Path(env["BTX_GATE_PREFIX"]) / "bin" / "btx-cli"
        cli.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        result = subprocess.run(["sh", "-c", gate.STOP_SCRIPT], env=env, capture_output=True, text=True, check=False)
        self.assertTrue(self.gone_within(pid, 5))
        self.assertIn(f"stopped-by-signal pid={pid}", result.stdout)

    def test_stop_script_without_a_node_does_nothing(self) -> None:
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "BTX_GATE_DATADIR": str(self.work / "none")}
        result = subprocess.run(["sh", "-c", gate.STOP_SCRIPT], env=env, capture_output=True, text=True, check=False)
        self.assertEqual((result.returncode, result.stdout), (0, ""))

    def test_a_timeout_runs_the_stop_in_the_same_root(self) -> None:
        root = self.work / "root"
        (root / "tmp").mkdir(parents=True)
        archive = make_archive(self.work)
        calls: list[list[str]] = []

        def fake_run(command: list[str], **_options: object) -> subprocess.CompletedProcess[str]:
            calls.append(command)
            if len(calls) == 1:
                raise subprocess.TimeoutExpired(command, 5)
            return subprocess.CompletedProcess(command, 0, stdout="stopped pid=7\n", stderr="")

        with mock.patch.object(gate, "rootfs_problem", return_value=None), \
                mock.patch.object(gate.subprocess, "run", side_effect=fake_run):
            passed, output = gate.run_image("proot", str(root), archive, 18943, [], 5)
        self.assertFalse(passed)
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0][:3], ["proot", "-r", str(root)])
        self.assertEqual(calls[0][-1], gate.START_SCRIPT)
        self.assertEqual(calls[1][:3], ["proot", "-r", str(root)])
        self.assertEqual(calls[1][-1], gate.STOP_SCRIPT)
        self.assertEqual([a for a in calls[0] if a.startswith("BTX_GATE_")], [a for a in calls[1] if a.startswith("BTX_GATE_")])
        self.assertIn("timed out after 5s", output)
        self.assertIn("stopped pid=7", output)
        self.assertEqual(list((root / "tmp").iterdir()), [])


class MainTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.work = pathlib.Path(self._tmp.name)

    def root(self, name: str) -> str:
        path = self.work / name
        (path / "tmp").mkdir(parents=True)
        return str(path)

    def run_main(self, argv: list[str], completed: subprocess.CompletedProcess[str] | None = None) -> tuple[int, str]:
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            if completed is None:
                code = gate.main(argv)
            else:
                with mock.patch.object(gate.subprocess, "run", return_value=completed), \
                        mock.patch.object(gate, "rootfs_problem", return_value=None), \
                        mock.patch.object(gate.shutil, "which", return_value="/usr/local/bin/proot"):
                    code = gate.main(argv)
        return code, out.getvalue() + err.getvalue()

    def test_an_engine_that_is_not_installed_is_a_failure_not_a_traceback(self) -> None:
        archive = make_archive(self.work)
        with mock.patch.object(gate.shutil, "which", return_value=None):
            code, text = self.run_main(["--archive", str(archive), "--image", self.root("noble"), "--engine", "proot"])
        self.assertEqual(code, 1)
        self.assertIn("proot is not on PATH", text)

    def test_missing_archive_is_an_error(self) -> None:
        code, text = self.run_main(["--archive", str(self.work / "nope.tar.gz"), "--image", "x"])
        self.assertEqual(code, 2)
        self.assertIn("no such archive", text)

    def test_only_tar_gz_is_accepted(self) -> None:
        zipped = self.work / "btx.zip"
        zipped.write_bytes(b"")
        code, text = self.run_main(["--archive", str(zipped), "--image", "x"])
        self.assertEqual(code, 2)
        self.assertIn(".tar.gz", text)

    def test_pass_and_fail_are_reported_per_image(self) -> None:
        archive = make_archive(self.work)
        ok = subprocess.CompletedProcess([], 0, stdout="gate-ok\n", stderr="")
        noble = self.root("noble")
        code, text = self.run_main(["--archive", str(archive), "--image", noble], ok)
        self.assertEqual(code, 0)
        self.assertIn(f"PASS {noble} (proot)", text)
        bad = subprocess.CompletedProcess([], 22, stdout="step=-version exit=127\nlibpython3.12.so.1.0\n", stderr="")
        trixie = self.root("trixie")
        code, text = self.run_main(["--archive", str(archive), "--image", trixie, "--image", self.root("plucky")], bad)
        self.assertEqual(code, 1)
        self.assertIn(f"FAIL {trixie} (proot)", text)
        self.assertIn("libpython3.12.so.1.0", text)
        self.assertIn("FAIL 2 of 2 image(s)", text)

    def test_exit_zero_without_the_marker_is_a_failure(self) -> None:
        archive = make_archive(self.work)
        silent = subprocess.CompletedProcess([], 0, stdout="", stderr="")
        code, _ = self.run_main(["--archive", str(archive), "--image", self.root("noble")], silent)
        self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
