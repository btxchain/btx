#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Self-contained regression harness for contrib/autoupdate/install.sh.

The harness fakes only the expensive build and signature tools. It runs the
real installer script against a local signed-manifest shape and live target
processes so process targeting and pre-stop failure behavior are observable.
"""

import json
import os
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import textwrap
import time


REPO_ROOT = Path(__file__).resolve().parents[2]
INSTALLER = REPO_ROOT / "contrib" / "autoupdate" / "install.sh"

PROCESS_CODE = r"""
import os
from pathlib import Path
import signal
import sys
import time

datadir = Path(sys.argv[1].split("=", 1)[1])
datadir.mkdir(parents=True, exist_ok=True)
(datadir / "pid").write_text(str(os.getpid()), encoding="utf8")

def handle_term(signum, frame):
    (datadir / "term.received").write_text(str(signum), encoding="utf8")
    raise SystemExit(0)

signal.signal(signal.SIGTERM, handle_term)
while True:
    time.sleep(1)
"""


def write_executable(path, text):
    path.write_text(textwrap.dedent(text).lstrip(), encoding="utf8")
    path.chmod(0o755)


def run(cmd, **kwargs):
    return subprocess.run(cmd, check=True, text=True, **kwargs)


def create_source_repo(root):
    source = root / "source-repo"
    source.mkdir()
    (source / "README.md").write_text("fake BTX source\n", encoding="utf8")
    run(["git", "init", "-q"], cwd=source)
    run(["git", "config", "user.email", "test@example.invalid"], cwd=source)
    run(["git", "config", "user.name", "Auto Update Test"], cwd=source)
    run(["git", "add", "README.md"], cwd=source)
    run(["git", "commit", "-q", "-m", "initial"], cwd=source)
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source, text=True).strip()
    return source, commit


def create_fake_tools(root):
    tools = root / "tools"
    tools.mkdir()

    write_executable(
        tools / "cmake",
        r"""
        #!/usr/bin/env python3
        import os
        from pathlib import Path
        import sys

        def append_log(message):
            log = os.environ.get("BTX_TEST_ACTION_LOG")
            if log:
                with open(log, "a", encoding="utf8") as out:
                    out.write(message + "\n")

        argv = sys.argv[1:]
        append_log("cmake " + " ".join(argv))

        if "--build" in argv:
            if os.environ.get("BTX_TEST_BUILD_FAIL") in {"1", "build"}:
                sys.exit(43)

            build_dir = Path(argv[argv.index("--build") + 1])
            bin_dir = build_dir / "bin"
            bin_dir.mkdir(parents=True, exist_ok=True)

            (bin_dir / "btxd").write_text('''#!/bin/sh
        if [ "${1:-}" = "--version" ]; then
          case "${BTX_TEST_BINARY_VERIFY_FAIL:-}" in
            btxd|all) exit 31 ;;
          esac
          echo "BTX fake btxd"
          exit 0
        fi
        # Restarted as a daemon: optionally simulate a crash-looping bad release so the installer's
        # health probe + rollback can be exercised; otherwise come up healthy and stay alive.
        datadir=""
        for arg in "$@"; do
          case "$arg" in -datadir=*) datadir="${arg#-datadir=}" ;; esac
        done
        if [ -n "$datadir" ]; then
          printf '%s\\n' "$$" > "$datadir/pid"
          # Healthy = leave a readiness marker. Unhealthy = stay alive (so the basic liveness check
          # passes) but never become ready, so the RPC health probe fails and triggers rollback.
          if [ "${BTX_TEST_RESTART_UNHEALTHY:-0}" != "1" ]; then
            : > "$datadir/node.ready"
          fi
        fi
        # Short sleeps so that when the test SIGTERMs this shell on cleanup, any orphaned child
        # sleep exits within ~1s instead of lingering. Trap TERM/INT for a prompt exit too.
        trap 'exit 0' TERM INT
        while : ; do sleep 1; done
        ''', encoding="utf8")
            (bin_dir / "btx-cli").write_text('''#!/bin/sh
        if [ "${1:-}" = "--version" ]; then
          case "${BTX_TEST_BINARY_VERIFY_FAIL:-}" in
            btx-cli|all) exit 32 ;;
          esac
          echo "BTX fake btx-cli"
          exit 0
        fi

        datadir=""
        stop_requested=0
        probe_requested=0
        for arg in "$@"; do
          case "$arg" in
            -datadir=*) datadir="${arg#-datadir=}" ;;
            stop) stop_requested=1 ;;
            uptime|getblockchaininfo) probe_requested=1 ;;
          esac
        done

        if [ "$stop_requested" = "1" ]; then
          printf 'btx-cli stop datadir=%s args=%s\n' "$datadir" "$*" >> "$BTX_TEST_ACTION_LOG"
          if [ -n "$datadir" ]; then
            printf 'stop\n' > "$datadir/stop.called"
            rm -f "$datadir/node.ready"
            if [ -f "$datadir/pid" ]; then
              kill -TERM "$(cat "$datadir/pid")" 2>/dev/null || true
            fi
          fi
          exit 0
        fi

        if [ "$probe_requested" = "1" ]; then
          # Healthy iff the daemon came up and left its readiness marker with a live pid.
          if [ -n "$datadir" ] && [ -f "$datadir/node.ready" ] && [ -f "$datadir/pid" ] && kill -0 "$(cat "$datadir/pid")" 2>/dev/null; then
            echo 1; exit 0
          fi
          exit 60
        fi

        printf 'btx-cli args=%s\n' "$*" >> "$BTX_TEST_ACTION_LOG"
        exit 0
        ''', encoding="utf8")
            (bin_dir / "btxd").chmod(0o755)
            (bin_dir / "btx-cli").chmod(0o755)
            sys.exit(0)

        if os.environ.get("BTX_TEST_BUILD_FAIL") == "configure":
            sys.exit(42)

        if "-B" in argv:
            Path(argv[argv.index("-B") + 1]).mkdir(parents=True, exist_ok=True)
        sys.exit(0)
        """,
    )

    write_executable(
        tools / "openssl",
        r"""
        #!/bin/sh
        printf 'openssl %s\n' "$*" >> "$BTX_TEST_ACTION_LOG"
        exit 0
        """,
    )

    write_executable(
        tools / "pgrep",
        r"""
        #!/bin/sh
        printf '%s\n' "$*" >> "$BTX_TEST_PGREP_LOG"
        if [ -n "${BTX_TEST_PGREP_PIDS:-}" ]; then
          printf '%b\n' "$BTX_TEST_PGREP_PIDS"
          exit 0
        fi
        if [ -n "${BTX_TEST_PGREP_PID:-}" ]; then
          printf '%s\n' "$BTX_TEST_PGREP_PID"
          exit 0
        fi
        exit 1
        """,
    )

    write_executable(
        tools / "c++",
        r"""
        #!/bin/sh
        exit 0
        """,
    )

    return tools


def create_manifest(root, source_repo, commit):
    origin = root / "origin"
    origin.mkdir()
    manifest = {
        "version": "99.0.0",
        "repo_url": str(source_repo),
        "script_url": (origin / "install.sh").as_uri(),
        "sig_url": (origin / "version.txt.sig").as_uri(),
        "git_ref": commit,
        "git_commit": commit,
    }
    (origin / "version.txt").write_text(json.dumps(manifest), encoding="utf8")
    (origin / "version.txt.sig").write_text("signature\n", encoding="utf8")
    (origin / "install.sh").write_text("#!/bin/sh\nexit 0\n", encoding="utf8")
    pub = root / "release.pub"
    pub.write_text("fake pubkey\n", encoding="utf8")
    return origin, pub


def start_fake_node(datadir):
    proc = subprocess.Popen(
        [sys.executable, "-c", PROCESS_CODE, f"-datadir={datadir}"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if (datadir / "pid").exists():
            return proc
        if proc.poll() is not None:
            raise AssertionError(f"fake node exited early with {proc.returncode}")
        time.sleep(0.05)
    raise AssertionError("fake node did not write pid file")


def stop_process(proc):
    if proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)


class Scenario:
    def __init__(self, name, extra_env=None):
        self.name = name
        self.extra_env = extra_env or {}
        self.tmp = None
        self.target = None
        self.distractor = None

    def __enter__(self):
        self.tmp = Path(tempfile.mkdtemp(prefix=f"btx-autoupdate-{self.name}-"))
        self.source_repo, self.commit = create_source_repo(self.tmp)
        self.tools = create_fake_tools(self.tmp)
        self.origin, self.pub = create_manifest(self.tmp, self.source_repo, self.commit)
        self.target_datadir = self.tmp / "target-datadir"
        self.distractor_datadir = self.tmp / "distractor-datadir"
        self.target = start_fake_node(self.target_datadir)
        self.distractor = start_fake_node(self.distractor_datadir)
        self.action_log = self.tmp / "actions.log"
        self.pgrep_log = self.tmp / "pgrep.log"
        return self

    def __exit__(self, exc_type, exc, tb):
        stop_process(self.target)
        stop_process(self.distractor)
        shutil.rmtree(self.tmp)

    def run_installer(self):
        env = os.environ.copy()
        env.update(
            {
                "PATH": f"{self.tools}{os.pathsep}{env['PATH']}",
                "HOME": str(self.tmp / "home"),
                "TMPDIR": str(self.tmp / "tmp"),
                "BTX_MANIFEST_URL": (self.origin / "version.txt").as_uri(),
                "BTX_MANIFEST_SIG_URL": (self.origin / "version.txt.sig").as_uri(),
                "BTX_TRUSTED_ORIGIN": self.origin.as_uri(),
                "BTX_RELEASE_PUB": str(self.pub),
                "BTX_GIT_REF": self.commit,
                "BTX_INSTALL_ROOT": str(self.tmp / "install"),
                "BTX_LINK_DIR": str(self.tmp / "links"),
                "BTX_CACHE_ROOT": str(self.tmp / "cache"),
                "BTX_AUTO_RESTART": "0",
                "BTX_START_IF_STOPPED": "0",
                "BTX_ENSURE_RETAIN_INDEX": "0",
                "BTX_STOP_TIMEOUT_SECONDS": "2",
                "BTX_JOBS": "1",
                "BTX_AUTOUPDATE_PID": str(self.target.pid),
                "BTX_AUTOUPDATE_DATADIR": str(self.target_datadir),
                "BTX_AUTOUPDATE": "1",
                "BTX_UPDATER_TEST_ALLOW_NON_BTXD_PID": "1",
                "BTX_TEST_ACTION_LOG": str(self.action_log),
                "BTX_TEST_PGREP_LOG": str(self.pgrep_log),
                "BTX_TEST_PGREP_PID": str(self.distractor.pid),
            }
        )
        env.update(self.extra_env)
        (self.tmp / "tmp").mkdir()
        return subprocess.run(
            [str(INSTALLER)],
            cwd=self.tmp,
            env=env,
            text=True,
            capture_output=True,
            timeout=60,
        )


def assert_no_pgrep_call(scenario):
    if scenario.pgrep_log.exists() and scenario.pgrep_log.read_text(encoding="utf8").strip():
        raise AssertionError(f"installer called pgrep:\n{scenario.pgrep_log.read_text(encoding='utf8')}")


def assert_success(result):
    if result.returncode != 0:
        raise AssertionError(
            f"installer unexpectedly failed with {result.returncode}\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
        )


def assert_failure(result):
    if result.returncode == 0:
        raise AssertionError(f"installer unexpectedly succeeded\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}")


def test_explicit_pid_and_datadir_bypass_pgrep():
    with Scenario("exact-target") as scenario:
        result = scenario.run_installer()
        assert_success(result)
        scenario.target.wait(timeout=5)

        assert_no_pgrep_call(scenario)
        if scenario.distractor.poll() is not None:
            raise AssertionError("distractor process was stopped")
        if not (scenario.target_datadir / "stop.called").exists():
            raise AssertionError("target datadir did not receive stop command")
        if (scenario.distractor_datadir / "stop.called").exists():
            raise AssertionError("distractor datadir received stop command")


def test_build_failure_does_not_stop_target():
    with Scenario("build-fails", {"BTX_TEST_BUILD_FAIL": "build", "BTX_ENSURE_RETAIN_INDEX": "1"}) as scenario:
        result = scenario.run_installer()
        assert_failure(result)
        time.sleep(0.2)

        assert_no_pgrep_call(scenario)
        if scenario.target.poll() is not None:
            raise AssertionError("target process stopped after build failure")
        if (scenario.target_datadir / "stop.called").exists():
            raise AssertionError("stop command was issued after build failure")
        if (scenario.target_datadir / "btx.conf").exists():
            raise AssertionError("target config was mutated after build failure")


def test_binary_verification_failure_does_not_stop_target():
    with Scenario("binary-fails", {"BTX_TEST_BINARY_VERIFY_FAIL": "btxd", "BTX_ENSURE_RETAIN_INDEX": "1"}) as scenario:
        result = scenario.run_installer()
        assert_failure(result)
        time.sleep(0.2)

        assert_no_pgrep_call(scenario)
        if scenario.target.poll() is not None:
            raise AssertionError("target process stopped after binary verification failure")
        if (scenario.target_datadir / "stop.called").exists():
            raise AssertionError("stop command was issued after binary verification failure")
        if (scenario.target_datadir / "btx.conf").exists():
            raise AssertionError("target config was mutated after binary verification failure")


def test_manual_mode_refuses_ambiguous_processes():
    with Scenario("manual-ambiguous") as scenario:
        scenario.extra_env.update(
            {
                "BTX_AUTOUPDATE": "0",
                "BTX_AUTOUPDATE_PID": "",
                "BTX_AUTOUPDATE_DATADIR": "",
                "BTX_TEST_PGREP_PID": "",
                "BTX_TEST_PGREP_PIDS": f"{scenario.target.pid}\n{scenario.distractor.pid}",
            }
        )
        result = scenario.run_installer()
        assert_failure(result)
        time.sleep(0.2)

        if scenario.target.poll() is not None:
            raise AssertionError("target process stopped after ambiguous manual detection")
        if scenario.distractor.poll() is not None:
            raise AssertionError("distractor process stopped after ambiguous manual detection")
        if (scenario.target_datadir / "stop.called").exists():
            raise AssertionError("target received stop command after ambiguous manual detection")
        if (scenario.distractor_datadir / "stop.called").exists():
            raise AssertionError("distractor received stop command after ambiguous manual detection")


# A minimal btxd/btx-cli pair for a prebuilt tarball: --version works, the daemon writes a pid +
# readiness marker and stays alive, and btx-cli answers the health probe / stop. Mirrors the fake
# cmake-built binaries closely enough to drive the prebuilt install path.
PREBUILT_BTXD = """#!/bin/sh
if [ "${1:-}" = "--version" ]; then echo "BTX prebuilt btxd"; exit 0; fi
datadir=""
for arg in "$@"; do case "$arg" in -datadir=*) datadir="${arg#-datadir=}" ;; esac; done
if [ -n "$datadir" ]; then printf '%s\\n' "$$" > "$datadir/pid"; : > "$datadir/node.ready"; fi
trap 'exit 0' TERM INT
while : ; do sleep 1; done
"""

PREBUILT_BTXCLI = """#!/bin/sh
if [ "${1:-}" = "--version" ]; then echo "BTX prebuilt btx-cli"; exit 0; fi
datadir=""
probe=0
for arg in "$@"; do
  case "$arg" in
    -datadir=*) datadir="${arg#-datadir=}" ;;
    uptime|getblockchaininfo) probe=1 ;;
    stop) [ -n "$datadir" ] && { rm -f "$datadir/node.ready"; [ -f "$datadir/pid" ] && kill -TERM "$(cat "$datadir/pid")" 2>/dev/null; }; exit 0 ;;
  esac
done
if [ "$probe" = "1" ]; then
  if [ -n "$datadir" ] && [ -f "$datadir/node.ready" ] && [ -f "$datadir/pid" ] && kill -0 "$(cat "$datadir/pid")" 2>/dev/null; then echo 1; exit 0; fi
  exit 60
fi
exit 0
"""


def host_platform_keys():
    """Mirror detect_platform_keys() in install.sh for this host."""
    sysname = platform.system()
    os_name = {"Linux": "linux", "Darwin": "darwin"}.get(sysname, sysname.lower())
    arch = platform.machine()
    if arch in ("amd64", "x86_64"):
        arch = "x86_64"
    elif arch in ("arm64", "aarch64"):
        arch = "aarch64"
    keys = []
    if os_name == "linux":
        libc = "musl" if (list(Path("/lib").glob("ld-musl-*")) or "musl" in (platform.libc_ver()[0] or "").lower()) else "glibc"
        keys.append(f"{os_name}-{arch}-{libc}")
        if arch == "aarch64":
            keys.append(f"{os_name}-arm64-{libc}")
    else:
        keys.append(f"{os_name}-{arch}")
        if arch == "aarch64":
            keys.append(f"{os_name}-arm64")
    return keys


def build_prebuilt_tarball(tmp, tar_path):
    staging = tmp / "prebuilt-staging"
    bindir = staging / "bin"
    bindir.mkdir(parents=True)
    write_executable(bindir / "btxd", PREBUILT_BTXD)
    write_executable(bindir / "btx-cli", PREBUILT_BTXCLI)
    with tarfile.open(tar_path, "w:gz") as tar:
        tar.add(bindir / "btxd", arcname="bin/btxd")
        tar.add(bindir / "btx-cli", arcname="bin/btx-cli")


def _kill_datadir_daemon(datadir):
    pidf = Path(datadir) / "pid"
    if pidf.exists():
        try:
            os.kill(int(pidf.read_text().strip()), signal.SIGTERM)
        except (OSError, ValueError):
            pass


def test_healthy_restart_passes_health_probe():
    with Scenario("healthy-restart", {"BTX_AUTO_RESTART": "1"}) as scenario:
        try:
            result = scenario.run_installer()
            assert_success(result)
            if not (scenario.target_datadir / "node.ready").exists():
                raise AssertionError("restarted node never reported healthy")
            if "rolled back" in (result.stdout + result.stderr):
                raise AssertionError(f"a healthy update was spuriously rolled back:\n{result.stderr}")
            # Observability: the status log records the run reaching a healthy completion (N3).
            status = scenario.tmp / "install" / "status.jsonl"
            if not status.exists():
                raise AssertionError("installer did not write a status log")
            status_text = status.read_text(encoding="utf8")
            for needle in ('"stage": "health-probe", "state": "healthy"', '"stage": "complete", "state": "ok"'):
                if needle not in status_text:
                    raise AssertionError(f"status log missing {needle!r}:\n{status_text}")
        finally:
            _kill_datadir_daemon(scenario.target_datadir)


def test_unhealthy_restart_triggers_rollback_path():
    # New binary stays up but never becomes RPC-healthy -> probe fails. With no previous release to
    # roll back to, the installer must abort (non-zero) with a health-probe message rather than
    # silently leaving the node on a bad binary.
    with Scenario("unhealthy-restart", {"BTX_AUTO_RESTART": "1", "BTX_TEST_RESTART_UNHEALTHY": "1"}) as scenario:
        try:
            result = scenario.run_installer()
            assert_failure(result)
            if "health probe" not in (result.stdout + result.stderr):
                raise AssertionError(f"expected a health-probe failure message; got:\n{result.stderr}")
        finally:
            _kill_datadir_daemon(scenario.target_datadir)


def _add_prebuilt_to_manifest(scenario):
    """Augment the scenario's signed manifest with a prebuilt entry for this host, returning the
    platform key used."""
    tar_path = scenario.origin / "btx-prebuilt.tar.gz"
    build_prebuilt_tarball(scenario.tmp, tar_path)
    (scenario.origin / "btx-prebuilt.tar.gz.sig").write_text("signature\n", encoding="utf8")
    key = host_platform_keys()[0]
    manifest = json.loads((scenario.origin / "version.txt").read_text(encoding="utf8"))
    manifest["prebuilt"] = {
        key: {
            "url": tar_path.as_uri(),
            "sig_url": (scenario.origin / "btx-prebuilt.tar.gz.sig").as_uri(),
        }
    }
    (scenario.origin / "version.txt").write_text(json.dumps(manifest), encoding="utf8")
    return key


def test_prebuilt_binary_is_used_without_source_build():
    with Scenario("prebuilt", {"BTX_AUTO_RESTART": "1"}) as scenario:
        try:
            key = _add_prebuilt_to_manifest(scenario)
            result = scenario.run_installer()
            assert_success(result)

            # The installed release came from the signed prebuilt, not a source build.
            release_manifest = json.loads((scenario.tmp / "install" / "current" / "manifest.json").read_text(encoding="utf8"))
            if release_manifest.get("source") != "prebuilt":
                raise AssertionError(f"expected source=prebuilt, got {release_manifest!r}")
            if release_manifest.get("platform") != key:
                raise AssertionError(f"expected platform={key}, got {release_manifest.get('platform')!r}")

            # No source build was performed.
            actions = scenario.action_log.read_text(encoding="utf8") if scenario.action_log.exists() else ""
            if "cmake --build" in actions or "--build" in actions:
                raise AssertionError(f"source build ran despite a usable prebuilt:\n{actions}")

            # Health probe passed and observability recorded the prebuilt install.
            status = (scenario.tmp / "install" / "status.jsonl").read_text(encoding="utf8")
            if '"stage": "prebuilt", "state": "installed"' not in status:
                raise AssertionError(f"status log missing prebuilt install:\n{status}")
            if not (scenario.target_datadir / "node.ready").exists():
                raise AssertionError("prebuilt node never reported healthy")
        finally:
            _kill_datadir_daemon(scenario.target_datadir)


def test_prebuilt_falls_back_to_source_when_disabled():
    with Scenario("prebuilt-disabled", {"BTX_AUTO_RESTART": "1", "BTX_PREFER_PREBUILT": "0"}) as scenario:
        try:
            _add_prebuilt_to_manifest(scenario)
            result = scenario.run_installer()
            assert_success(result)
            # With prebuilt disabled, the source-build path runs (cmake invoked) and the release is
            # marked as a source build.
            actions = scenario.action_log.read_text(encoding="utf8") if scenario.action_log.exists() else ""
            if "--build" not in actions:
                raise AssertionError(f"expected a source build when prebuilt disabled:\n{actions}")
            release_manifest = json.loads((scenario.tmp / "install" / "current" / "manifest.json").read_text(encoding="utf8"))
            if release_manifest.get("source") == "prebuilt":
                raise AssertionError("used prebuilt despite BTX_PREFER_PREBUILT=0")
        finally:
            _kill_datadir_daemon(scenario.target_datadir)


def main():
    if not INSTALLER.exists():
        raise SystemExit(f"installer not found: {INSTALLER}")

    tests = [
        test_explicit_pid_and_datadir_bypass_pgrep,
        test_build_failure_does_not_stop_target,
        test_binary_verification_failure_does_not_stop_target,
        test_manual_mode_refuses_ambiguous_processes,
        test_healthy_restart_passes_health_probe,
        test_unhealthy_restart_triggers_rollback_path,
        test_prebuilt_binary_is_used_without_source_build,
        test_prebuilt_falls_back_to_source_when_disabled,
    ]
    for test in tests:
        test()
        print(f"PASS {test.__name__}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        signal.raise_signal(signal.SIGINT)
