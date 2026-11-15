#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Start a release archive's btxd on regtest inside a clean OS image.

verify_release_btxd.py runs `btxd -version` on the host that builds the release.
That host has the libraries the build used. A daemon that needs a library the
target machine does not have can therefore pass the gate and fail on the
operator's machine: the header of verify_release_btxd.py describes the 0.34 CUDA
tarball and the 0.34.8-rc1 glibc floor, where `ldd` looked clean. This script
runs the start in an image that holds only the base system, so a missing
library fails here first.

Per root filesystem it unpacks the archive, requires `btxd -version` to exit 0,
starts a regtest node, requires `getblockchaininfo` to report chain "regtest",
sends `stop` and waits until the RPC no longer answers. A node that is still
running after a failed step is stopped before the script leaves; when --timeout
ends a run, a second command in the same root stops it. Pass the exact file that
will be published; an archive that relies on host libraries is expected to fail.

    verify_archive_clean_start.py --archive btx-0.34.16-x86_64-linux-gnu.tar.gz \\
        --engine proot --image /srv/noble --image /srv/trixie --btxd-arg=-swapnet=1

--image is the directory of a root filesystem such as
`debootstrap --variant=minbase noble /srv/noble`:
- --engine proot (the default when proot is on PATH) binds /proc, /dev and /sys
  and needs no root, only write access to the root's /tmp. It first checks that
  proot can see files in the root: the proot 5.1.0 of Ubuntu 24.04 could not
  where this was tested; one built from the v5.4.0 tag could.
- --engine chroot needs root and /proc mounted in the root first
  (`mount -t proc proc /srv/noble/proc`); without /proc the loader cannot expand
  $ORIGIN run paths, so a correct archive would fail. It refuses instead.
The start runs with an empty environment apart from PATH and a HOME inside its
datadir, so nothing is left in the image afterwards.

Arguments for btxd beyond the regtest defaults go after --btxd-arg (repeatable;
an argument cannot contain spaces).
Run it once with --btxd-arg=-swapnet=0 and once with --btxd-arg=-swapnet=1: a
-swapnet=1 node that cannot start SwapNet stops during init and fails the start.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

DEFAULT_RPC_PORT = 18943
OUTPUT_TAIL_LINES = 12

# Runs inside the image (sh, tar and the base system only). Each failing step
# prints "step=..." and exits with its own code so the caller can tell them
# apart. The environment carries every setting.
START_SCRIPT = r"""
set -u -f
prefix=${BTX_GATE_PREFIX:-/opt/btx}
datadir=${BTX_GATE_DATADIR:-/tmp/btx-gate-datadir}
port=${BTX_GATE_RPCPORT:-18943}
btxd="$prefix/bin/btxd"
cli="$prefix/bin/btx-cli"
started=0
stop_node() { "$cli" -regtest -rpcport="$port" -datadir="$datadir" stop > /dev/null 2>&1; }
cleanup() {
  rc=$?
  if [ "$started" -eq 1 ]; then
    stop_node
    n=0
    while [ "$n" -lt 20 ] && "$cli" -regtest -rpcport="$port" -datadir="$datadir" getblockcount > /dev/null 2>&1; do
      n=$((n + 1)); sleep 1
    done
    pid=$(cat "$datadir"/regtest/btxd.pid 2> /dev/null) && [ -n "$pid" ] && kill -0 "$pid" 2> /dev/null && kill "$pid" 2> /dev/null
  fi
  exit "$rc"
}
trap cleanup EXIT
mkdir -p "$prefix" "$datadir" "${HOME:-$datadir}" || { echo "step=mkdir"; exit 20; }
tar -xzf "$BTX_GATE_ARCHIVE" -C "$prefix" --strip-components=1 || { echo "step=extract"; exit 21; }
out=$("$btxd" -version 2>&1); rc=$?
if [ "$rc" -ne 0 ]; then
  echo "step=-version exit=$rc"; echo "$out" | tail -n 6; exit 22
fi
"$btxd" -regtest=1 -autoupdate=0 -listen=0 -dnsseed=0 -rpcport="$port" -port=$((port + 1)) \
  -datadir="$datadir" ${BTX_GATE_ARGS:-} -daemon > "$datadir/start.out" 2>&1; rc=$?
if [ "$rc" -ne 0 ]; then
  echo "step=start exit=$rc"; tail -n 6 "$datadir/start.out"; exit 23
fi
started=1
n=0; info=""; gone=""
while [ "$n" -lt "${BTX_GATE_WAIT:-90}" ]; do
  if info=$("$cli" -regtest -rpcport="$port" -datadir="$datadir" getblockchaininfo 2>/dev/null); then break; fi
  info=""
  if grep -q "Shutdown: done" "$datadir/regtest/debug.log" 2> /dev/null; then gone="the daemon exited; "; break; fi
  n=$((n + 1)); sleep 1
done
case "$info" in
  *'"chain": "regtest"'*) ;;
  *) echo "step=getblockchaininfo ${gone}no regtest answer after ${n}s"
     grep -E "SwapNet: startup failed|Error: |error: " "$datadir/regtest/debug.log" 2> /dev/null | tail -n 3
     tail -n 6 "$datadir/regtest/debug.log" 2> /dev/null; exit 24 ;;
esac
stop_node
n=0
while "$cli" -regtest -rpcport="$port" -datadir="$datadir" getblockcount > /dev/null 2>&1; do
  n=$((n + 1))
  if [ "$n" -ge "${BTX_GATE_STOP_WAIT:-60}" ]; then echo "step=stop btxd still answering after ${n}s"; exit 25; fi
  sleep 1
done
started=0
echo "gate-ok"
"""

# Runs in the same image after --timeout ended the start script: the daemon
# forked away from it, so `stop` it, wait for its pid, then SIGTERM it.
STOP_SCRIPT = r"""
set -u
datadir=${BTX_GATE_DATADIR:-/tmp/btx-gate-datadir}
port=${BTX_GATE_RPCPORT:-18943}
cli="${BTX_GATE_PREFIX:-/opt/btx}/bin/btx-cli"
pid=$(cat "$datadir"/regtest/btxd.pid 2> /dev/null) || exit 0
[ -n "$pid" ] && kill -0 "$pid" 2> /dev/null || exit 0
n=0
while [ "$n" -lt "${BTX_GATE_STOP_WAIT:-60}" ] && kill -0 "$pid" 2> /dev/null; do
  # The RPC may still be warming up when --timeout fires, so ask again every 5 s.
  [ $((n % 5)) -eq 0 ] && "$cli" -regtest -rpcport="$port" -datadir="$datadir" stop > /dev/null 2>&1
  n=$((n + 1)); sleep 1
done
if kill -0 "$pid" 2> /dev/null; then kill "$pid" 2> /dev/null; echo "stopped-by-signal pid=$pid"; else echo "stopped pid=$pid"; fi
"""
STOP_TIMEOUT = 120.0


def script_env(archive_in_image: str, rpc_port: int, btxd_args: list[str]) -> dict[str, str]:
    return {
        "BTX_GATE_ARCHIVE": archive_in_image,
        "BTX_GATE_PREFIX": f"/opt/btx-gate-{os.getpid()}",
        "BTX_GATE_DATADIR": f"/tmp/btx-gate-{os.getpid()}",
        "HOME": f"/tmp/btx-gate-{os.getpid()}/home",
        "BTX_GATE_RPCPORT": str(rpc_port),
        "BTX_GATE_ARGS": " ".join(btxd_args),
    }


CLEAN_ENV = ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"]
# A file only the root has (the host has no such path), run through its shebang: a
# proot that passes guest paths to the kernel untranslated cannot find or run it.
PROBE_TEXT = "#!/bin/sh\necho proot-sees-files\n"


def env_args(env: dict[str, str]) -> list[str]:
    return ["/usr/bin/env", "-i", *CLEAN_ENV, *(f"{key}={value}" for key, value in env.items())]


def chroot_command(rootfs: str, env: dict[str, str], script: str = START_SCRIPT) -> list[str]:
    return ["chroot", rootfs, *env_args(env), "sh", "-c", script]


def proot_command(rootfs: str, env: dict[str, str], script: str = START_SCRIPT) -> list[str]:
    return ["proot", "-r", rootfs, "-b", "/proc", "-b", "/dev", "-b", "/sys", "-w", "/", *env_args(env), "sh", "-c", script]


def rootfs_command(engine: str, rootfs: str, env: dict[str, str], script: str = START_SCRIPT) -> list[str]:
    return (proot_command if engine == "proot" else chroot_command)(rootfs, env, script)


def stop_command(engine: str, rootfs: str, env: dict[str, str]) -> list[str]:
    """The command that stops a node the start script left behind when --timeout ended it."""
    return rootfs_command(engine, rootfs, env, STOP_SCRIPT)


def rootfs_problem(engine: str, rootfs: str) -> str | None:
    """Why this root filesystem cannot give a true result with this engine, or None."""
    if not Path(rootfs).is_dir():
        return f"{rootfs} is not a directory"
    if engine == "chroot":
        if os.name != "posix" or os.geteuid() != 0:
            return "the chroot engine needs root"
        if not (Path(rootfs) / "proc" / "self").exists():
            return (f"/proc is not mounted in {rootfs}; mount it first (mount -t proc proc {rootfs}/proc). "
                    "Without it the loader cannot expand $ORIGIN, so a correct archive would fail.")
        return None
    if not (Path(rootfs) / "tmp").is_dir():
        return f"{rootfs} has no tmp directory"
    marker = Path(rootfs) / "tmp" / f"btx-gate-probe-{os.getpid()}"
    try:
        marker.write_text(PROBE_TEXT, encoding="ascii")
        marker.chmod(0o755)
        script = f"test -x /tmp/{marker.name} && /tmp/{marker.name}"
        probe = subprocess.run(proot_command(rootfs, {}, script), capture_output=True, text=True, timeout=60, check=False)
    except subprocess.TimeoutExpired:
        return f"proot did not run a file in {rootfs} within 60s"
    finally:
        marker.unlink(missing_ok=True)
    if "proot-sees-files" not in probe.stdout:
        return f"proot cannot see files in {rootfs} (the proot 5.1.0 of Ubuntu 24.04 cannot; 5.4.0 can): {tail(probe.stderr)}"
    return None


def tail(text: str) -> str:
    return "\n".join(text.strip().splitlines()[-OUTPUT_TAIL_LINES:])


def run_image(engine: str, image: str, archive: Path, rpc_port: int, btxd_args: list[str], timeout: float) -> tuple[bool, str]:
    """Return (passed, output tail) for one root filesystem."""
    problem = rootfs_problem(engine, image)
    if problem:
        return False, problem
    # A name of our own, set as copied only once the copy exists, so cleanup never
    # removes a file that was already in the root (or the archive itself).
    target = Path(image) / "tmp" / f"btx-gate-{os.getpid()}-{archive.name}"
    copied: Path | None = None
    env = script_env(f"/tmp/{target.name}", rpc_port, btxd_args)
    try:
        shutil.copyfile(archive, target)
        copied = target
        result = subprocess.run(rootfs_command(engine, image, env), capture_output=True, text=True, timeout=timeout, check=False)
        output = (result.stdout or "") + (result.stderr or "")
        return result.returncode == 0 and "gate-ok" in result.stdout, tail(output)
    except subprocess.TimeoutExpired:
        note = ""
        try:
            done = subprocess.run(stop_command(engine, image, env), capture_output=True, text=True, timeout=STOP_TIMEOUT, check=False)
            note = ((done.stdout or "") + (done.stderr or "")).strip()
        except (subprocess.TimeoutExpired, OSError) as error:
            note = f"stop failed: {error}"
        return False, tail("\n".join(line for line in (f"timed out after {timeout:.0f}s", note) if line))
    except OSError as error:
        return False, f"could not run: {error}"
    finally:
        if copied is not None:
            copied.unlink(missing_ok=True)
            shutil.rmtree(Path(image) / env["BTX_GATE_PREFIX"].lstrip("/"), ignore_errors=True)
            shutil.rmtree(Path(image) / env["BTX_GATE_DATADIR"].lstrip("/"), ignore_errors=True)


def pick_engine(requested: str) -> str | None:
    if requested == "auto":
        return "proot" if shutil.which("proot") else "chroot"
    return requested if requested == "chroot" or shutil.which(requested) else None


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--archive", required=True, type=Path, help="Linux release archive (.tar.gz) to start.")
    parser.add_argument("--image", action="append", required=True, help="Root filesystem directory; repeatable.")
    parser.add_argument("--engine", choices=("auto", "proot", "chroot"), default="auto")
    parser.add_argument("--btxd-arg", action="append", default=[], help="Extra btxd argument; repeatable.")
    parser.add_argument("--rpc-port", type=int, default=DEFAULT_RPC_PORT, help="RPC port (the P2P port is one above).")
    parser.add_argument("--timeout", type=float, default=300.0, help="Seconds allowed per image.")
    args = parser.parse_args(argv)

    if not args.archive.is_file():
        print(f"verify_archive_clean_start: FAIL no such archive: {args.archive}", file=sys.stderr)
        return 2
    if not args.archive.name.endswith(".tar.gz"):
        print("verify_archive_clean_start: FAIL only .tar.gz Linux archives are supported", file=sys.stderr)
        return 2

    failures = 0
    for image in args.image:
        engine = pick_engine(args.engine)
        if engine is None:
            print(f"verify_archive_clean_start: FAIL {image}: {args.engine} is not on PATH", file=sys.stderr)
            failures += 1
            continue
        passed, output = run_image(engine, image, args.archive, args.rpc_port, args.btxd_arg, args.timeout)
        if passed:
            print(f"verify_archive_clean_start: PASS {image} ({engine})")
        else:
            failures += 1
            print(f"verify_archive_clean_start: FAIL {image} ({engine})")
            for line in output.splitlines():
                print(f"    {line}")
    if failures:
        print(f"verify_archive_clean_start: FAIL {failures} of {len(args.image)} image(s)")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
