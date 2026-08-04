#!/usr/bin/env python3
"""Two-node trusted-mirror rehearsal: strict-device archive + trusted mirror.

Archive runs matmulvalidation=consensus with attestation signing/serving.
Mirror runs matmulvalidation=trusted and accepts Profile-1 ExactReplay via
signed quorum from the archive — no local GPU required.

Remote-archive usage (run on the non-GPU host; the signer file already exists
on the archive and is never copied through the mirror host):

  python3 -u contrib/matmul-v4/two-node-trusted-mirror-rehearsal.py \\
    --archive-host gpu-archive.example.invalid \\
    --archive-user operator \\
    --archive-btxd /path/to/gpu-build/bin/btxd \\
    --archive-cli /path/to/gpu-build/bin/btx-cli \\
    --archive-backend metal \\
    --strict-proof-mode winner-reseal-authority \\
    --archive-signer-wif-file /secure/archive-only/signer.wif \\
    --mirror-btxd /path/to/cpu-build/bin/btxd \\
    --mirror-cli /path/to/cpu-build/bin/btx-cli \\
    --source-revision <exact-40-character-commit> \\
    --archive-btxd-sha256 <reviewed-sha256> \\
    --archive-cli-sha256 <reviewed-sha256> \\
    --mirror-btxd-sha256 <reviewed-sha256> \\
    --mirror-cli-sha256 <reviewed-sha256> \\
    --signer-pub-file /secure/path/to/signer.pub

One-host Apple Metal rehearsal:

  python3 -u contrib/matmul-v4/two-node-trusted-mirror-rehearsal.py \\
    --archive-local \\
    --archive-btxd /path/to/metal-build/bin/btxd \\
    --archive-cli /path/to/metal-build/bin/btx-cli \\
    --archive-backend metal \\
    --strict-proof-mode winner-reseal-authority \\
    --mirror-btxd /path/to/cpu-build/bin/btxd \\
    --mirror-cli /path/to/cpu-build/bin/btx-cli \\
    --signer-wif-file /secure/path/to/disposable-regtest-signer.wif \\
    --signer-pub-file /secure/path/to/disposable-regtest-signer.pub \\
    --source-revision <exact-40-character-commit> \\
    --archive-btxd-sha256 <reviewed-sha256> \\
    --archive-cli-sha256 <reviewed-sha256> \\
    --mirror-btxd-sha256 <reviewed-sha256> \\
    --mirror-cli-sha256 <reviewed-sha256>

The matching uppercase environment variables remain supported as defaults.
"""
from __future__ import annotations

import atexit
import argparse
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path, PurePosixPath

sys.path.insert(0, str(Path(__file__).resolve().parent))
import evidence_source_identity as EVIDENCE_IDENTITY  # noqa: E402

ACTIVATION = 6
DISABLED = 2_147_483_647

ARCHIVE_HOST = ""
ARCHIVE_USER = ""
ARCHIVE_BTXD = ""
ARCHIVE_CLI = ""
ARCHIVE_BACKEND = ""
ARCHIVE_LOCAL = False
ARCHIVE_PROC: subprocess.Popen | None = None
ARCHIVE_LOG = None
ARCHIVE_REMOTE_PID = ""
ARCHIVE_REMOTE_LAUNCH_ATTEMPTED = False
MIRROR_BTXD = Path()
MIRROR_CLI = Path()
SIGNER_WIF_FILE = Path()
ARCHIVE_SIGNER_WIF_FILE = ""
SIGNER_PUB = ""
RUNTIME_ROOT = Path(tempfile.gettempdir())
ARCHIVE_DD = ""
MIRROR_DD: Path | None = None
ARCHIVE_RPC = 19821
ARCHIVE_P2P = 19822
MIRROR_RPC = 19831
MIRROR_P2P = 19832
OUT = Path("trusted-mirror-result.json")
KEEP_ARTIFACTS = False
STRICT_PROOF_MODE = ""
REPO_ROOT = Path(__file__).resolve().parents[2]
SOURCE_REVISION = ""
SOURCE_TREE_FINGERPRINT = ""
ARCHIVE_BTXD_SHA256 = ""
ARCHIVE_CLI_SHA256 = ""
MIRROR_BTXD_SHA256 = ""
MIRROR_CLI_SHA256 = ""
REMOTE_ARCHIVE_NAME = re.compile(r"btx-trusted-archive\.[A-Za-z0-9]{6}")
REMOTE_PID = re.compile(r"[1-9][0-9]{0,9}")
COMPRESSED_PUBKEY = re.compile(r"(?:02|03)[0-9a-fA-F]{64}")
PUBLIC_CLASS = re.compile(r"[A-Za-z0-9_.+-]+")
PRODUCTION_BLOCKS = 3
REMOTE_TERM_WAIT_SECONDS = 30
REMOTE_KILL_WAIT_SECONDS = 10


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--archive-local",
        action="store_true",
        default=os.environ.get("BTX_TRUSTED_MIRROR_ARCHIVE_LOCAL") == "1",
        help="run the strict-device archive locally without SSH or a tunnel",
    )
    parser.add_argument("--archive-host", default=os.environ.get("ARCHIVE_HOST"))
    parser.add_argument("--archive-user", default=os.environ.get("ARCHIVE_USER"))
    parser.add_argument("--archive-btxd", default=os.environ.get("ARCHIVE_BTXD"))
    parser.add_argument("--archive-cli", default=os.environ.get("ARCHIVE_CLI"))
    parser.add_argument(
        "--archive-backend",
        choices=("cuda", "metal", "hip"),
        default=os.environ.get("BTX_TRUSTED_MIRROR_ARCHIVE_BACKEND"),
        help="required strict archive provider family",
    )
    parser.add_argument(
        "--strict-proof-mode",
        choices=("winner-reseal-authority",),
        default=os.environ.get("BTX_TRUSTED_MIRROR_STRICT_PROOF_MODE"),
        help=(
            "required self-mining archive proof mode; this two-node runner "
            "supports only winner-reseal-authority"
        ),
    )
    parser.add_argument("--mirror-btxd", type=Path, default=os.environ.get("MIRROR_BTXD"))
    parser.add_argument("--mirror-cli", type=Path, default=os.environ.get("MIRROR_CLI"))
    parser.add_argument(
        "--signer-wif-file", type=Path, default=os.environ.get("SIGNER_WIF_FILE")
    )
    parser.add_argument(
        "--archive-signer-wif-file",
        default=os.environ.get("ARCHIVE_SIGNER_WIF_FILE"),
        help="pre-provisioned archive-only WIF path for remote mode",
    )
    parser.add_argument(
        "--signer-pub-file", type=Path, default=os.environ.get("SIGNER_PUB_FILE")
    )
    parser.add_argument(
        "--runtime-root",
        type=Path,
        default=Path(os.environ.get("BTX_TRUSTED_MIRROR_TMPDIR", tempfile.gettempdir())),
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=Path(os.environ.get("BTX_TRUSTED_MIRROR_OUT", "trusted-mirror-result.json")),
    )
    parser.add_argument(
        "--keep-artifacts",
        action="store_true",
        default=os.environ.get("BTX_TRUSTED_MIRROR_KEEP_ARTIFACTS") == "1",
    )
    parser.add_argument(
        "--source-revision", default=os.environ.get("BTX_SOURCE_REVISION")
    )
    parser.add_argument(
        "--archive-startup-timeout",
        type=int,
        default=int(os.environ.get("BTX_TRUSTED_MIRROR_STARTUP_TIMEOUT", "600")),
    )
    parser.add_argument(
        "--mine-timeout",
        type=int,
        default=int(os.environ.get("BTX_TRUSTED_MIRROR_MINE_TIMEOUT", "900")),
    )
    parser.add_argument(
        "--mirror-sync-timeout",
        type=int,
        default=int(os.environ.get("BTX_TRUSTED_MIRROR_SYNC_TIMEOUT", "600")),
    )
    for option, env_name in (
        ("archive-btxd-sha256", "ARCHIVE_BTXD_SHA256"),
        ("archive-cli-sha256", "ARCHIVE_CLI_SHA256"),
        ("mirror-btxd-sha256", "MIRROR_BTXD_SHA256"),
        ("mirror-cli-sha256", "MIRROR_CLI_SHA256"),
    ):
        parser.add_argument(f"--{option}", default=os.environ.get(env_name))
    return parser


def validate_args(
    parser: argparse.ArgumentParser, args: argparse.Namespace
) -> argparse.Namespace:
    required = (
        ("archive_btxd", "--archive-btxd", "ARCHIVE_BTXD"),
        ("archive_cli", "--archive-cli", "ARCHIVE_CLI"),
        ("archive_backend", "--archive-backend", "BTX_TRUSTED_MIRROR_ARCHIVE_BACKEND"),
        ("strict_proof_mode", "--strict-proof-mode", "BTX_TRUSTED_MIRROR_STRICT_PROOF_MODE"),
        ("mirror_btxd", "--mirror-btxd", "MIRROR_BTXD"),
        ("mirror_cli", "--mirror-cli", "MIRROR_CLI"),
        ("signer_pub_file", "--signer-pub-file", "SIGNER_PUB_FILE"),
        ("source_revision", "--source-revision", "BTX_SOURCE_REVISION"),
        ("archive_btxd_sha256", "--archive-btxd-sha256", "ARCHIVE_BTXD_SHA256"),
        ("archive_cli_sha256", "--archive-cli-sha256", "ARCHIVE_CLI_SHA256"),
        ("mirror_btxd_sha256", "--mirror-btxd-sha256", "MIRROR_BTXD_SHA256"),
        ("mirror_cli_sha256", "--mirror-cli-sha256", "MIRROR_CLI_SHA256"),
    )
    for name, option, env_name in required:
        if getattr(args, name) in (None, ""):
            parser.error(f"{option} is required (or set {env_name})")
    if args.strict_proof_mode != "winner-reseal-authority":
        parser.error(
            "--strict-proof-mode must be winner-reseal-authority for this "
            "two-node self-mining rehearsal"
        )
    if args.archive_local:
        if args.signer_wif_file in (None, ""):
            parser.error(
                "--signer-wif-file is required with --archive-local "
                "(use a disposable regtest key)"
            )
        if args.archive_signer_wif_file not in (None, ""):
            parser.error(
                "--archive-signer-wif-file is only valid for a remote archive"
            )
    else:
        for name, option, env_name in (
            ("archive_host", "--archive-host", "ARCHIVE_HOST"),
            ("archive_user", "--archive-user", "ARCHIVE_USER"),
            (
                "archive_signer_wif_file",
                "--archive-signer-wif-file",
                "ARCHIVE_SIGNER_WIF_FILE",
            ),
        ):
            if getattr(args, name) in (None, ""):
                parser.error(f"{option} is required (or set {env_name})")
        if args.signer_wif_file not in (None, ""):
            parser.error(
                "remote mode never reads or uploads --signer-wif-file; "
                "pre-provision --archive-signer-wif-file on the archive"
            )
        try:
            args.archive_signer_wif_file = validate_remote_file_path(
                args.archive_signer_wif_file,
                "--archive-signer-wif-file",
            )
        except RuntimeError as error:
            parser.error(str(error))
    for name, option in (
        ("mirror_btxd", "--mirror-btxd"),
        ("mirror_cli", "--mirror-cli"),
        ("signer_pub_file", "--signer-pub-file"),
    ):
        path = getattr(args, name)
        if not path.is_file():
            parser.error(f"{option} is not a file: {path}")
    if args.archive_local:
        args.archive_btxd = Path(args.archive_btxd)
        args.archive_cli = Path(args.archive_cli)
        for name, option in (
            ("archive_btxd", "--archive-btxd"),
            ("archive_cli", "--archive-cli"),
            ("signer_wif_file", "--signer-wif-file"),
        ):
            path = getattr(args, name)
            if not path.is_file():
                parser.error(f"{option} is not a file: {path}")
        args.signer_wif_file = args.signer_wif_file.resolve()
        if "\n" in str(args.signer_wif_file) or "\r" in str(args.signer_wif_file):
            parser.error("--signer-wif-file is not safe for a configuration value")
        try:
            require_private_local_file(
                args.signer_wif_file, "--signer-wif-file"
            )
        except RuntimeError as error:
            parser.error(str(error))
    if not args.runtime_root.is_dir():
        parser.error(f"--runtime-root is not a directory: {args.runtime_root}")
    for name, option in (
        ("archive_startup_timeout", "--archive-startup-timeout"),
        ("mine_timeout", "--mine-timeout"),
        ("mirror_sync_timeout", "--mirror-sync-timeout"),
    ):
        value = getattr(args, name)
        if value < 60 or value > 3600:
            parser.error(f"{option} must be between 60 and 3600 seconds")
    try:
        args.source_revision = EVIDENCE_IDENTITY.resolve_commit(
            REPO_ROOT, args.source_revision
        )
        args.source_tree_fingerprint = EVIDENCE_IDENTITY.tree_fingerprint(
            REPO_ROOT, args.source_revision
        )
        EVIDENCE_IDENTITY.verify_binary(
            args.mirror_btxd, args.mirror_btxd_sha256, "mirror_btxd_sha256"
        )
        EVIDENCE_IDENTITY.verify_binary(
            args.mirror_cli, args.mirror_cli_sha256, "mirror_cli_sha256"
        )
        if args.archive_local:
            EVIDENCE_IDENTITY.verify_binary(
                args.archive_btxd, args.archive_btxd_sha256,
                "archive_btxd_sha256",
            )
            EVIDENCE_IDENTITY.verify_binary(
                args.archive_cli, args.archive_cli_sha256,
                "archive_cli_sha256",
            )
        else:
            EVIDENCE_IDENTITY.require_hex(
                args.archive_btxd_sha256, EVIDENCE_IDENTITY.HEX64,
                "archive_btxd_sha256",
            )
            EVIDENCE_IDENTITY.require_hex(
                args.archive_cli_sha256, EVIDENCE_IDENTITY.HEX64,
                "archive_cli_sha256",
            )
    except EVIDENCE_IDENTITY.EvidenceIdentityError as error:
        parser.error(str(error))
    return args


def cleanup_local_artifacts() -> None:
    if MIRROR_DD is not None and not KEEP_ARTIFACTS:
        shutil.rmtree(MIRROR_DD, ignore_errors=True)


def sh_local(cmd: list[str], timeout: int = 120) -> str:
    r = subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=timeout)
    return r.stdout.strip()


def sh_remote(remote_cmd: str, timeout: int = 120, input_text: str | None = None) -> str:
    r = subprocess.run(
        ["ssh", "-o", "BatchMode=yes", f"{ARCHIVE_USER}@{ARCHIVE_HOST}", remote_cmd],
        check=True,
        capture_output=True,
        text=True,
        input=input_text,
        timeout=timeout,
    )
    return r.stdout.strip()


def remote_sha256(path: str) -> str:
    quoted = shlex.quote(path)
    command = (
        f"if command -v sha256sum >/dev/null 2>&1; then sha256sum -- {quoted}; "
        f"elif command -v shasum >/dev/null 2>&1; then shasum -a 256 -- {quoted}; "
        "else exit 127; fi"
    )
    output = sh_remote(command)
    digest = output.split(maxsplit=1)[0] if output else ""
    return EVIDENCE_IDENTITY.require_hex(
        digest, EVIDENCE_IDENTITY.HEX64, "remote_binary_sha256"
    )


def validate_remote_file_path(value: str, option: str) -> str:
    """Accept an absolute, non-traversing archive-owned file path."""
    if (not isinstance(value, str) or "\x00" in value or "\n" in value or
            "\r" in value):
        raise RuntimeError(f"{option} is not a safe remote path")
    path = PurePosixPath(value)
    if (not path.is_absolute() or ".." in path.parts or
            path.parent == PurePosixPath("/")):
        raise RuntimeError(f"{option} must be an absolute archive-owned file path")
    return str(path)


def require_private_local_file(path: Path, option: str) -> None:
    """Require owner-only mode bits on a local secret file."""
    if stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise RuntimeError(f"{option} must not be accessible by group or others")


def remote_private_file_check_command(path: str) -> str:
    """Build a Linux/macOS check for a readable owner-only remote file."""
    quoted = shlex.quote(path)
    return (
        f"test -f {quoted} && test -r {quoted} && "
        f"mode=$(if stat -c '%a' {quoted} >/dev/null 2>&1; "
        f"then stat -c '%a' {quoted}; else stat -f '%Lp' {quoted}; fi) && "
        "case \"$mode\" in *[0-7]00) ;; *) exit 13 ;; esac"
    )


def validate_remote_archive_dir(value: str) -> str:
    """Accept only the exact private mktemp directory shape we requested."""
    if not isinstance(value, str) or "\x00" in value or "\n" in value:
        raise RuntimeError("remote mktemp returned an unsafe archive datadir")
    path = PurePosixPath(value)
    if (not path.is_absolute() or ".." in path.parts or
            path.parent == PurePosixPath("/") or
            REMOTE_ARCHIVE_NAME.fullmatch(path.name) is None):
        raise RuntimeError("remote mktemp returned an unsafe archive datadir")
    return str(path)


def validate_remote_pid(value: str, label: str = "remote archive PID") -> str:
    """Accept one positive decimal PID and no surrounding command output."""
    if not isinstance(value, str):
        raise RuntimeError(f"{label} is not a valid process ID")
    value = value.strip()
    if REMOTE_PID.fullmatch(value) is None:
        raise RuntimeError(f"{label} is not a valid process ID")
    return value


def remote_stop_archive_command(pid: str, datadir: str) -> str:
    """Build a bounded, identity-checked TERM/KILL shutdown command."""
    pid = validate_remote_pid(pid)
    datadir = validate_remote_archive_dir(datadir)
    quoted_datadir = shlex.quote(datadir)
    quoted_pidfile = shlex.quote(f"{datadir}/regtest/btxd.pid")
    return (
        f"pid={pid}; datadir={quoted_datadir}; pidfile={quoted_pidfile}; "
        "if kill -0 \"$pid\" 2>/dev/null; then "
        "cmd=$(ps -p \"$pid\" -o command= 2>/dev/null) || exit 16; "
        "case \"$cmd\" in *\"$datadir\"*) ;; *) exit 16 ;; esac; "
        "if test -r \"$pidfile\"; then "
        "recorded=$(tr -d '[:space:]' < \"$pidfile\"); "
        "test \"$recorded\" = \"$pid\" || exit 15; fi; "
        "kill -TERM \"$pid\" 2>/dev/null || true; "
        "i=0; while kill -0 \"$pid\" 2>/dev/null && "
        f"test \"$i\" -lt {REMOTE_TERM_WAIT_SECONDS}; do "
        "sleep 1; i=$((i + 1)); done; fi; "
        "if kill -0 \"$pid\" 2>/dev/null; then "
        "kill -KILL \"$pid\" 2>/dev/null || true; "
        "i=0; while kill -0 \"$pid\" 2>/dev/null && "
        f"test \"$i\" -lt {REMOTE_KILL_WAIT_SECONDS}; do "
        "sleep 1; i=$((i + 1)); done; fi; "
        "if kill -0 \"$pid\" 2>/dev/null; then exit 14; fi"
    )


def validate_signer_pubkey(value: str) -> str:
    """Reject config injection before btxd performs full curve validation."""
    value = value.strip()
    if COMPRESSED_PUBKEY.fullmatch(value) is None:
        raise RuntimeError(
            "--signer-pub-file must contain one compressed secp256k1 public key"
        )
    return value.lower()


def mirror_rpc(*args: str, timeout: int = 120):
    if MIRROR_DD is None:
        raise RuntimeError("mirror datadir is not initialized")
    out = sh_local(
        [
            str(MIRROR_CLI),
            f"-datadir={MIRROR_DD}",
            f"-rpcport={MIRROR_RPC}",
            "-rpcuser=u",
            "-rpcpassword=p",
            "-rpcclienttimeout=0",
            *args,
        ],
        timeout=timeout,
    )
    if not out:
        return None
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return out


def archive_rpc(*args: str, timeout: int = 120):
    if ARCHIVE_LOCAL:
        out = sh_local(
            [
                str(ARCHIVE_CLI),
                f"-datadir={ARCHIVE_DD}",
                f"-rpcport={ARCHIVE_RPC}",
                "-rpcuser=u",
                "-rpcpassword=p",
                "-rpcclienttimeout=0",
                *args,
            ],
            timeout=timeout,
        )
        if not out:
            return None
        try:
            return json.loads(out)
        except json.JSONDecodeError:
            return out
    # Escape for remote shell
    joined = " ".join(shlex.quote(a) for a in args)
    cmd = (
        f"{shlex.quote(ARCHIVE_CLI)} -datadir={shlex.quote(ARCHIVE_DD)} "
        f"-rpcport={ARCHIVE_RPC} "
        f"-rpcuser=u -rpcpassword=p -rpcclienttimeout=0 {joined}"
    )
    out = sh_remote(cmd, timeout=timeout)
    if not out:
        return None
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return out


def wait_rpc(fn, label: str, timeout: float = 120) -> None:
    deadline = time.monotonic() + timeout
    last = ""
    while time.monotonic() < deadline:
        try:
            fn("getblockchaininfo")
            return
        except Exception as exc:  # noqa: BLE001
            last = str(exc)
            time.sleep(0.5)
    raise RuntimeError(f"{label} RPC not ready: {last}")


def cleanup_archive() -> None:
    global ARCHIVE_PROC, ARCHIVE_REMOTE_PID, ARCHIVE_REMOTE_LAUNCH_ATTEMPTED
    if not ARCHIVE_DD:
        return
    if ARCHIVE_LOCAL:
        if ARCHIVE_PROC is not None and ARCHIVE_PROC.poll() is None:
            ARCHIVE_PROC.terminate()
            try:
                ARCHIVE_PROC.wait(timeout=30)
            except subprocess.TimeoutExpired:
                ARCHIVE_PROC.kill()
                ARCHIVE_PROC.wait(timeout=10)
        ARCHIVE_PROC = None
        if not KEEP_ARTIFACTS:
            shutil.rmtree(ARCHIVE_DD, ignore_errors=True)
        return
    if ARCHIVE_REMOTE_LAUNCH_ATTEMPTED:
        pid = ARCHIVE_REMOTE_PID
        if not pid:
            launcher_pid_file = shlex.quote(
                f"{ARCHIVE_DD}/rehearsal-launch.pid"
            )
            try:
                pid = validate_remote_pid(
                    sh_remote(f"cat {launcher_pid_file}"),
                    "remote archive launcher PID",
                )
            except Exception as error:
                raise RuntimeError(
                    "cannot establish the remote archive PID; refusing to "
                    "remove its datadir"
                ) from error
        try:
            sh_remote(
                remote_stop_archive_command(pid, ARCHIVE_DD),
                timeout=(
                    REMOTE_TERM_WAIT_SECONDS + REMOTE_KILL_WAIT_SECONDS + 10
                ),
            )
        except Exception as error:
            raise RuntimeError(
                "remote archive did not reach a verified stopped state; "
                "refusing to remove its datadir"
            ) from error
        ARCHIVE_REMOTE_PID = ""
        ARCHIVE_REMOTE_LAUNCH_ATTEMPTED = False
    if not KEEP_ARTIFACTS:
        sh_remote(f"rm -rf -- {shlex.quote(ARCHIVE_DD)}")


def _require_object(parent: dict, key: str, path: str) -> dict:
    value = parent.get(key)
    if not isinstance(value, dict):
        raise RuntimeError(f"getmininginfo schema error: {path} must be an object")
    return value


def _require_bool(parent: dict, key: str, path: str) -> bool:
    value = parent.get(key)
    if not isinstance(value, bool):
        raise RuntimeError(f"getmininginfo schema error: {path} must be a boolean")
    return value


def _require_nonnegative_int(parent: dict, key: str, path: str) -> int:
    value = parent.get(key)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise RuntimeError(
            f"getmininginfo schema error: {path} must be a non-negative integer"
        )
    return value


def _require_public_string(parent: dict, key: str, path: str) -> str:
    value = parent.get(key)
    if (not isinstance(value, str) or not value or
            PUBLIC_CLASS.fullmatch(value) is None):
        raise RuntimeError(
            f"getmininginfo schema error: {path} must be a public class token"
        )
    return value


def derive_archive_host_class(canary: dict, expected_provider_family: str) -> str:
    """Derive a publication-safe machine class from runtime canary fields."""
    family = _require_public_string(
        canary, "provider_family", "production_canary.provider_family"
    )
    architecture = _require_public_string(
        canary, "device_architecture", "production_canary.device_architecture"
    )
    if family != expected_provider_family:
        raise RuntimeError(
            "production canary provider family does not match --archive-backend"
        )
    return f"{family}_{architecture}_exactreplay_archive"


def extract_strict_replay_evidence(
    mining_info: object, *, expected_revision: str | None = None,
    expected_fingerprint: str | None = None,
    expected_provider_family: str | None = None,
) -> tuple[dict, dict, dict]:
    """Return and validate the strict-replay evidence exposed by getmininginfo."""
    if not isinstance(mining_info, dict):
        raise RuntimeError("getmininginfo schema error: response must be an object")
    runtime = _require_object(mining_info, "backend_runtime", "backend_runtime")
    rc = _require_object(runtime, "rc_exact_replay", "backend_runtime.rc_exact_replay")
    canary = _require_object(
        rc, "production_canary", "backend_runtime.rc_exact_replay.production_canary"
    )
    validation = _require_object(
        rc, "last_validation", "backend_runtime.rc_exact_replay.last_validation"
    )
    for key in (
        "production_eligible", "startup_canary_passed", "activation_ready"
    ):
        if not _require_bool(rc, key, f"backend_runtime.rc_exact_replay.{key}"):
            raise RuntimeError(f"strict archive readiness gate is false: {key}")
    resolved_provider = _require_public_string(
        rc, "resolved_provider", "backend_runtime.rc_exact_replay.resolved_provider"
    )
    if not _require_bool(canary, "passed", "production_canary.passed"):
        raise RuntimeError("production canary did not pass")
    if not _require_bool(
        canary, "exact_manifest_match", "production_canary.exact_manifest_match"
    ):
        raise RuntimeError("production canary did not exactly match the manifest")
    if _require_nonnegative_int(
        canary, "device_macs", "production_canary.device_macs"
    ) == 0:
        raise RuntimeError("production canary recorded no device MACs")
    if _require_nonnegative_int(
        canary, "cpu_fallbacks", "production_canary.cpu_fallbacks"
    ) != 0:
        raise RuntimeError("production canary used CPU fallback")
    canary_provider = _require_public_string(
        canary, "provider", "production_canary.provider"
    )
    canary_family = _require_public_string(
        canary, "provider_family", "production_canary.provider_family"
    )
    _require_public_string(
        canary, "device_architecture", "production_canary.device_architecture"
    )
    if canary_provider != resolved_provider:
        raise RuntimeError("resolved provider and canary provider differ")
    if expected_provider_family is not None:
        if canary_family != expected_provider_family:
            raise RuntimeError(
                "production canary provider family does not match --archive-backend"
            )
        if not canary_provider.startswith(expected_provider_family + "_"):
            raise RuntimeError(
                "production canary provider is incoherent with its provider family"
            )

    available = _require_bool(validation, "available", "last_validation.available")
    if available:
        if not _require_bool(
            validation, "require_device", "last_validation.require_device"
        ):
            raise RuntimeError("last validation did not require a device")
        if not _require_bool(
            validation, "fully_accelerated", "last_validation.fully_accelerated"
        ):
            raise RuntimeError("last validation was not fully accelerated")
        for key in ("cpu_gemm_calls", "cpu_gemm_fallbacks"):
            if _require_nonnegative_int(
                validation, key, f"last_validation.{key}"
            ) != 0:
                raise RuntimeError(f"last validation recorded nonzero {key}")
        validation_provider = _require_public_string(
            validation, "provider", "last_validation.provider"
        )
        if expected_provider_family is not None and not validation_provider.startswith(
            expected_provider_family + "_"
        ):
            raise RuntimeError(
                "last validation provider is incoherent with --archive-backend"
            )
    if (expected_revision is None) != (expected_fingerprint is None):
        raise RuntimeError("source revision and fingerprint must be supplied together")
    if expected_revision is not None and expected_fingerprint is not None:
        try:
            EVIDENCE_IDENTITY.validate_canary_build_identity(
                canary,
                revision=expected_revision,
                fingerprint=expected_fingerprint,
                prefix="production_canary",
            )
        except EVIDENCE_IDENTITY.EvidenceIdentityError as error:
            raise RuntimeError(f"getmininginfo provenance error: {error}") from error
    return rc, canary, validation


def extract_scheduler_evidence(mining_info: object) -> dict:
    if not isinstance(mining_info, dict):
        raise RuntimeError("getmininginfo schema error: response must be an object")
    runtime = _require_object(mining_info, "backend_runtime", "backend_runtime")
    scheduler = _require_object(
        runtime, "rc_accelerator_scheduler",
        "backend_runtime.rc_accelerator_scheduler",
    )
    lanes = _require_object(scheduler, "lanes", "rc_accelerator_scheduler.lanes")
    for lane_name in ("candidate_mining", "winner_reseal"):
        lane = _require_object(lanes, lane_name, f"rc_accelerator_scheduler.lanes.{lane_name}")
        _require_nonnegative_int(
            lane, "completions",
            f"rc_accelerator_scheduler.lanes.{lane_name}.completions",
        )
        last_execution = lane.get("last_execution_s")
        if not isinstance(last_execution, (int, float)) or isinstance(last_execution, bool):
            raise RuntimeError(
                "getmininginfo schema error: rc_accelerator_scheduler.lanes."
                f"{lane_name}.last_execution_s must be numeric"
            )
    _require_nonnegative_int(
        scheduler, "release_invariant_violations",
        "rc_accelerator_scheduler.release_invariant_violations",
    )
    authority = _require_object(
        scheduler, "winner_reseal_authority",
        "rc_accelerator_scheduler.winner_reseal_authority",
    )
    for field in (
        "published", "consumed", "rejected_not_block_target",
        "rejected_not_production_ready", "invalidated_before_consume",
        "expired", "evicted", "misses", "entries",
    ):
        _require_nonnegative_int(
            authority, field, f"winner_reseal_authority.{field}"
        )
    last_provider = authority.get("last_provider")
    if not isinstance(last_provider, str) or (
        last_provider and PUBLIC_CLASS.fullmatch(last_provider) is None
    ):
        raise RuntimeError(
            "getmininginfo schema error: winner_reseal_authority.last_provider "
            "must be empty or a public class token"
        )
    consumed_by_provider = _require_object(
        authority, "consumed_by_provider",
        "winner_reseal_authority.consumed_by_provider",
    )
    for provider, count in consumed_by_provider.items():
        if (not isinstance(provider, str) or not provider or
                PUBLIC_CLASS.fullmatch(provider) is None):
            raise RuntimeError(
                "getmininginfo schema error: winner_reseal_authority."
                "consumed_by_provider keys must be public provider tokens"
            )
        if not isinstance(count, int) or isinstance(count, bool) or count < 0:
            raise RuntimeError(
                "getmininginfo schema error: winner_reseal_authority."
                "consumed_by_provider values must be non-negative integers"
            )
    return scheduler


def validate_archive_strict_proof(
    *, mode: str, baseline_mining_info: object, final_mining_info: object,
    expected_provider: str,
) -> dict:
    """Close this self-mining runner's exact winner-reseal proof, fail closed."""
    if mode != "winner-reseal-authority":
        raise RuntimeError(
            "the two-node self-mining rehearsal supports only "
            "winner-reseal-authority"
        )

    baseline = extract_scheduler_evidence(baseline_mining_info)
    final = extract_scheduler_evidence(final_mining_info)
    baseline_lanes = baseline["lanes"]
    final_lanes = final["lanes"]
    deltas = {}
    candidate_delta = (
        final_lanes["candidate_mining"]["completions"] -
        baseline_lanes["candidate_mining"]["completions"]
    )
    if candidate_delta < PRODUCTION_BLOCKS:
        raise RuntimeError(
            f"strict proof recorded only {candidate_delta} candidate_mining "
            f"completions; expected at least {PRODUCTION_BLOCKS}"
        )
    if final_lanes["candidate_mining"]["last_execution_s"] <= 0:
        raise RuntimeError("strict proof recorded no candidate_mining execution time")
    deltas["candidate_mining_completions"] = candidate_delta

    reseal_delta = (
        final_lanes["winner_reseal"]["completions"] -
        baseline_lanes["winner_reseal"]["completions"]
    )
    if reseal_delta != PRODUCTION_BLOCKS:
        raise RuntimeError(
            f"strict proof recorded {reseal_delta} winner_reseal completions; "
            f"expected exactly {PRODUCTION_BLOCKS}"
        )
    if final_lanes["winner_reseal"]["last_execution_s"] <= 0:
        raise RuntimeError("strict proof recorded no winner_reseal execution time")
    deltas["winner_reseal_completions"] = reseal_delta

    for label, scheduler in (("baseline", baseline), ("final", final)):
        if scheduler["release_invariant_violations"] != 0:
            raise RuntimeError(
                f"accelerator scheduler release invariant was violated in {label}"
            )
    baseline_authority = baseline["winner_reseal_authority"]
    final_authority = final["winner_reseal_authority"]
    if baseline_authority["entries"] != 0 or final_authority["entries"] != 0:
        raise RuntimeError(
            "winner-reseal authority store must be empty before and after proof"
        )
    for field in ("published", "consumed"):
        delta = final_authority[field] - baseline_authority[field]
        if delta != PRODUCTION_BLOCKS:
            raise RuntimeError(
                f"winner-reseal authority {field} changed by {delta}; "
                f"expected exactly {PRODUCTION_BLOCKS}"
            )
        deltas[f"authority_{field}"] = delta
    if deltas["authority_published"] != deltas["authority_consumed"]:
        raise RuntimeError("winner-reseal published and consumed deltas differ")
    for field in (
        "rejected_not_block_target", "rejected_not_production_ready",
        "invalidated_before_consume", "expired", "evicted", "misses",
    ):
        delta = final_authority[field] - baseline_authority[field]
        if delta != 0:
            raise RuntimeError(
                f"winner-reseal authority {field} changed by {delta} during proof"
            )
    if final_authority["last_provider"] != expected_provider:
        raise RuntimeError("winner-reseal authority provider differs from canary provider")
    baseline_providers = baseline_authority["consumed_by_provider"]
    final_providers = final_authority["consumed_by_provider"]
    all_providers = set(baseline_providers) | set(final_providers)
    provider_deltas = {
        provider: final_providers.get(provider, 0) -
        baseline_providers.get(provider, 0)
        for provider in all_providers
    }
    if provider_deltas != {expected_provider: PRODUCTION_BLOCKS}:
        raise RuntimeError(
            "winner-reseal consumed-provider deltas do not bind all three "
            "authorities to the canary provider"
        )
    return {
        "mode": mode,
        "provider": final_authority["last_provider"],
        **deltas,
        "candidate_last_execution_s": final_lanes["candidate_mining"]["last_execution_s"],
        "winner_reseal_last_execution_s": final_lanes["winner_reseal"]["last_execution_s"],
        "release_invariant_violations": final["release_invariant_violations"],
        "consumed_by_provider": provider_deltas,
    }


def validate_trusted_mirror_rehearsal(
    *, archive_services: object, mirror_services: object,
    archive_status: object, mirror_status: object, mirror_mode: object,
) -> None:
    """Prove the archive/mirror trust boundary before emitting ok=true."""
    if (not isinstance(archive_services, list) or
            not isinstance(mirror_services, list) or
            any(not isinstance(item, str) for item in archive_services + mirror_services)):
        raise RuntimeError("trusted-mirror schema error: service lists are required")
    required_archive = {"MATMUL_ATTESTATION_ARCHIVE", "MATMUL_CONSENSUS"}
    if not required_archive.issubset(set(archive_services)):
        raise RuntimeError("archive does not advertise required MatMul services")
    if ("MATMUL_TRUSTED_MIRROR" not in mirror_services or
            "MATMUL_CONSENSUS" in mirror_services or
            "MATMUL_ATTESTATION_ARCHIVE" in mirror_services):
        raise RuntimeError("mirror service separation is invalid")
    if mirror_mode != "trusted":
        raise RuntimeError("mirror validation mode is not trusted")
    if not isinstance(archive_status, dict) or not isinstance(mirror_status, dict):
        raise RuntimeError("trusted-mirror schema error: status objects are required")

    archive_required = {
        "configured": True,
        "trusted_mirror": False,
        "serves_attestations": True,
        "local_signer": True,
        "attestation_version": 2,
        "threshold": 1,
        "trusted_signers": 1,
    }
    mirror_required = {
        "configured": True,
        "trusted_mirror": True,
        "serves_attestations": False,
        "local_signer": False,
        "attestation_version": 2,
        "threshold": 1,
        "trusted_signers": 1,
    }
    for label, status, required in (
        ("archive", archive_status, archive_required),
        ("mirror", mirror_status, mirror_required),
    ):
        for field, expected in required.items():
            actual = status.get(field)
            type_ok = (
                actual is expected if isinstance(expected, bool)
                else isinstance(actual, int) and not isinstance(actual, bool)
            )
            if not type_ok or actual != expected:
                raise RuntimeError(
                    f"{label} trusted status {field} must equal {expected!r}"
                )
        context = status.get("replay_authority_context")
        try:
            EVIDENCE_IDENTITY.require_hex(
                context, EVIDENCE_IDENTITY.HEX64,
                f"{label}.replay_authority_context",
            )
        except EVIDENCE_IDENTITY.EvidenceIdentityError as error:
            raise RuntimeError(f"trusted-mirror schema error: {error}") from error
    if (mirror_status["replay_authority_context"] !=
            archive_status["replay_authority_context"]):
        raise RuntimeError("archive and mirror replay authority contexts differ")
    for field in ("accepted", "blocks_with_quorum"):
        value = mirror_status.get(field)
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            raise RuntimeError(f"mirror trusted status {field} must be at least 1")


def main(argv: list[str] | None = None) -> None:
    global ARCHIVE_DD, ARCHIVE_HOST, ARCHIVE_USER, ARCHIVE_BTXD, ARCHIVE_CLI
    global ARCHIVE_BACKEND, ARCHIVE_LOCAL, ARCHIVE_PROC, ARCHIVE_LOG
    global ARCHIVE_REMOTE_PID, ARCHIVE_REMOTE_LAUNCH_ATTEMPTED
    global ARCHIVE_SIGNER_WIF_FILE, STRICT_PROOF_MODE
    global MIRROR_BTXD, MIRROR_CLI, SIGNER_WIF_FILE, SIGNER_PUB
    global RUNTIME_ROOT, MIRROR_DD, OUT, KEEP_ARTIFACTS
    global SOURCE_REVISION, SOURCE_TREE_FINGERPRINT
    global ARCHIVE_BTXD_SHA256, ARCHIVE_CLI_SHA256
    global MIRROR_BTXD_SHA256, MIRROR_CLI_SHA256

    parser = build_arg_parser()
    args = validate_args(parser, parser.parse_args(argv))
    ARCHIVE_HOST = args.archive_host
    ARCHIVE_USER = args.archive_user
    ARCHIVE_BTXD = args.archive_btxd
    ARCHIVE_CLI = args.archive_cli
    ARCHIVE_BACKEND = args.archive_backend
    ARCHIVE_LOCAL = args.archive_local
    ARCHIVE_SIGNER_WIF_FILE = args.archive_signer_wif_file
    STRICT_PROOF_MODE = args.strict_proof_mode
    MIRROR_BTXD = args.mirror_btxd
    MIRROR_CLI = args.mirror_cli
    SIGNER_WIF_FILE = args.signer_wif_file
    try:
        SIGNER_PUB = validate_signer_pubkey(
            args.signer_pub_file.read_text(encoding="utf-8")
        )
    except RuntimeError as error:
        parser.error(str(error))
    RUNTIME_ROOT = args.runtime_root
    OUT = args.out
    KEEP_ARTIFACTS = args.keep_artifacts
    SOURCE_REVISION = args.source_revision
    SOURCE_TREE_FINGERPRINT = args.source_tree_fingerprint
    ARCHIVE_BTXD_SHA256 = args.archive_btxd_sha256
    ARCHIVE_CLI_SHA256 = args.archive_cli_sha256
    MIRROR_BTXD_SHA256 = args.mirror_btxd_sha256
    MIRROR_CLI_SHA256 = args.mirror_cli_sha256
    if not ARCHIVE_LOCAL:
        try:
            if remote_sha256(ARCHIVE_BTXD) != ARCHIVE_BTXD_SHA256:
                parser.error("archive btxd SHA256 does not match --archive-btxd-sha256")
            if remote_sha256(ARCHIVE_CLI) != ARCHIVE_CLI_SHA256:
                parser.error("archive btx-cli SHA256 does not match --archive-cli-sha256")
            sh_remote(remote_private_file_check_command(ARCHIVE_SIGNER_WIF_FILE))
        except (subprocess.SubprocessError, EVIDENCE_IDENTITY.EvidenceIdentityError) as error:
            parser.error(
                "cannot verify archive binary identity or private signer permissions "
                f"({type(error).__name__})"
            )
    MIRROR_DD = Path(
        tempfile.mkdtemp(prefix="btx-trusted-mirror-", dir=RUNTIME_ROOT)
    )
    atexit.register(cleanup_local_artifacts)

    if ARCHIVE_LOCAL:
        ARCHIVE_DD = tempfile.mkdtemp(
            prefix="btx-trusted-archive-", dir=RUNTIME_ROOT
        )
        Path(ARCHIVE_DD, "regtest").mkdir(mode=0o700)
        archive_signer_path = str(SIGNER_WIF_FILE)
    else:
        ARCHIVE_DD = validate_remote_archive_dir(
            sh_remote("mktemp -d \"${TMPDIR:-/tmp}/btx-trusted-archive.XXXXXX\"")
        )
        archive_regtest = f"{ARCHIVE_DD}/regtest"
        sh_remote(f"umask 077; mkdir -p {shlex.quote(archive_regtest)}")
        archive_signer_path = ARCHIVE_SIGNER_WIF_FILE
    atexit.register(cleanup_archive)

    common_regtest = f"""
regtest=1
server=1
dnsseed=0
fixedseeds=0
listen=1
discover=0
rpcuser=u
rpcpassword=p
fallbackfee=0.0002
debug=net
printtoconsole=0
matmulasyncverify=1
regtestmatmulbindingheight=2
regtestmatmulproductdigestheight=2
regtestmatmulrequireproductpayload=0
regtestmatmulv4height={ACTIVATION}
regtestbmx4cheight={ACTIVATION}
regtestdrltheight={DISABLED}
regtestrcheight={ACTIVATION}
regtestrccoupledheight={DISABLED}
regtestrcprofile=1
regtestrctoydims=0
regtestrccoupledtoydims=0
regtestmatmulltsealaspow=0
regtestmatmulv4dimension=4096
regtestmatmulv4maxdimension=4096
matmultrustedpubkey={SIGNER_PUB}
matmultrustedthreshold=1
matmultrustedwaitms=60000
"""

    archive_conf = common_regtest + f"""
matmulvalidation=consensus
matmulrcexecution=strict-device
matmulattestationsignerkeyfile={archive_signer_path}
matmulattestationserve=1
listenonion=0
allowdangerousnoban=1
whitelist=noban,in,out@127.0.0.1
[regtest]
port={ARCHIVE_P2P}
rpcport={ARCHIVE_RPC}
bind=127.0.0.1
rpcbind=127.0.0.1
rpcallowip=127.0.0.1
"""
    if ARCHIVE_LOCAL:
        archive_conf_path = Path(ARCHIVE_DD, "btx.conf")
        archive_conf_path.write_text(archive_conf, encoding="utf-8")
        archive_conf_path.chmod(0o600)
    else:
        sh_remote(
            f"umask 077; cat > {shlex.quote(ARCHIVE_DD + '/btx.conf')}",
            input_text=archive_conf,
        )

    # Remote mode tunnels only P2P. RPC remains an authenticated SSH command.
    # Local mode deliberately has no self-SSH tunnel: archive already owns the
    # loopback P2P port and a second bind would fail.
    tunnel = None
    if not ARCHIVE_LOCAL:
        tunnel = subprocess.Popen(
            [
                "ssh", "-o", "BatchMode=yes", "-o", "ExitOnForwardFailure=yes",
                "-N", "-L",
                f"127.0.0.1:{ARCHIVE_P2P}:127.0.0.1:{ARCHIVE_P2P}",
                f"{ARCHIVE_USER}@{ARCHIVE_HOST}",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        atexit.register(tunnel.terminate)
        time.sleep(1)
        if tunnel.poll() is not None:
            raise RuntimeError("SSH local forwarding failed before archive startup")

    mirror_conf = common_regtest + f"""
matmulvalidation=trusted
matmulrcexecution=strict-device
matmulattestationserve=0
listenonion=0
[regtest]
port={MIRROR_P2P}
rpcport={MIRROR_RPC}
connect=127.0.0.1:{ARCHIVE_P2P}
bind=127.0.0.1
rpcbind=127.0.0.1
rpcallowip=127.0.0.1
"""
    mirror_conf_path = MIRROR_DD / "btx.conf"
    mirror_conf_path.write_text(mirror_conf, encoding="utf-8")
    mirror_conf_path.chmod(0o600)

    archive_env = os.environ.copy()
    archive_env["BTX_MATMUL_V4_BACKEND"] = ARCHIVE_BACKEND
    archive_env["BTX_RC_ACCEL_POLICY"] = "production"
    if ARCHIVE_LOCAL:
        ARCHIVE_LOG = Path(ARCHIVE_DD, "stdout.log").open("w", encoding="utf-8")
        ARCHIVE_PROC = subprocess.Popen(
            [
                str(ARCHIVE_BTXD), f"-datadir={ARCHIVE_DD}",
                f"-conf={Path(ARCHIVE_DD, 'btx.conf')}",
            ],
            env=archive_env,
            stdout=ARCHIVE_LOG,
            stderr=subprocess.STDOUT,
        )
    else:
        ARCHIVE_REMOTE_LAUNCH_ATTEMPTED = True
        launcher_pid_file = shlex.quote(
            f"{ARCHIVE_DD}/rehearsal-launch.pid"
        )
        launch_output = sh_remote(
            "umask 077; "
            f"export BTX_MATMUL_V4_BACKEND={shlex.quote(ARCHIVE_BACKEND)} "
            "BTX_RC_ACCEL_POLICY=production; "
            f"nohup {shlex.quote(ARCHIVE_BTXD)} "
            f"-datadir={shlex.quote(ARCHIVE_DD)} "
            f"-conf={shlex.quote(ARCHIVE_DD + '/btx.conf')} "
            f">{shlex.quote(ARCHIVE_DD + '/stdout.log')} 2>&1 & "
            f"pid=$!; printf \"%s\\n\" \"$pid\" > {launcher_pid_file}; "
            "printf \"%s\\n\" \"$pid\""
        )
        ARCHIVE_REMOTE_PID = validate_remote_pid(
            launch_output, "remote archive launcher PID"
        )
    wait_rpc(archive_rpc, "archive", timeout=args.archive_startup_timeout)
    archive_rpc("createwallet", "miner")

    # Start local mirror
    mirror_log = (MIRROR_DD / "stdout.log").open("w")
    mirror_proc = subprocess.Popen(
        [str(MIRROR_BTXD), f"-datadir={MIRROR_DD}", f"-conf={mirror_conf_path}"],
        stdout=mirror_log,
        stderr=subprocess.STDOUT,
    )
    atexit.register(mirror_proc.terminate)
    try:
        wait_rpc(mirror_rpc, "mirror", timeout=args.archive_startup_timeout)
        # Wait until P2P link is up through the tunnel
        deadline = time.monotonic() + min(120, args.mirror_sync_timeout)
        while time.monotonic() < deadline:
            peers = mirror_rpc("getpeerinfo") or []
            if peers:
                print(f"mirror peers={[p.get('addr') for p in peers]}", flush=True)
                break
            time.sleep(1)
        else:
            raise RuntimeError("mirror never connected to the archive P2P endpoint")

        a_net = archive_rpc("getnetworkinfo")
        m_net = mirror_rpc("getnetworkinfo")
        a_services = a_net.get("localservicesnames", [])
        m_services = m_net.get("localservicesnames", [])
        print("archive_services", a_services, flush=True)
        print("mirror_services", m_services, flush=True)
        baseline_mining_info = archive_rpc("getmininginfo")

        # Mine through activation+2 on archive. This yields exactly three
        # production Profile-1 winners (heights 6, 7, and 8).
        timings = []
        for _ in range(ACTIVATION + 2):
            t0 = time.perf_counter()
            archive_rpc(
                "generatetoaddress", "1", archive_rpc("getnewaddress"),
                timeout=args.mine_timeout,
            )
            dt = time.perf_counter() - t0
            ah = archive_rpc("getblockcount")
            timings.append({"mined_height": ah, "archive_generate_s": round(dt, 3)})
            print(f"archive mined h={ah} in {dt:.3f}s", flush=True)

        tip = archive_rpc("getbestblockhash")
        deadline = time.monotonic() + args.mirror_sync_timeout
        while time.monotonic() < deadline:
            if mirror_rpc("getbestblockhash") == tip:
                break
            time.sleep(1)
        else:
            raise RuntimeError(
                "mirror did not catch tip; trusted="
                + json.dumps(mirror_rpc("getmatmultrustedstatus"))
            )

        archive_trusted = archive_rpc("getmatmultrustedstatus")
        trusted = mirror_rpc("getmatmultrustedstatus")
        mirror_mode = mirror_rpc("getblockchaininfo").get("matmulvalidationmode")
        validate_trusted_mirror_rehearsal(
            archive_services=a_services,
            mirror_services=m_services,
            archive_status=archive_trusted,
            mirror_status=trusted,
            mirror_mode=mirror_mode,
        )
        final_mining_info = archive_rpc("getmininginfo")
        archive_rc, canary, validation = extract_strict_replay_evidence(
            final_mining_info,
            expected_revision=SOURCE_REVISION,
            expected_fingerprint=SOURCE_TREE_FINGERPRINT,
            expected_provider_family=ARCHIVE_BACKEND,
        )
        strict_proof = validate_archive_strict_proof(
            mode=STRICT_PROOF_MODE,
            baseline_mining_info=baseline_mining_info,
            final_mining_info=final_mining_info,
            expected_provider=canary["provider"],
        )
        result = {
            "ok": True,
            "evidence_kind": "production_strict_trusted_mirror_rehearsal",
            "schema_version": 2,
            "production_shape": True,
            "archive_host_class": derive_archive_host_class(canary, ARCHIVE_BACKEND),
            "mirror_host_class": "cpu_trusted_mirror",
            "archive_provider_family": ARCHIVE_BACKEND,
            "strict_proof_mode": STRICT_PROOF_MODE,
            "trust_topology": "single-operator 1-of-1 trusted attestation",
            "trust_warning": (
                "The mirror is not an independently validating full node and "
                "inherits the archive signer's failures."
            ),
            "source_revision": SOURCE_REVISION,
            "source_tree_fingerprint": SOURCE_TREE_FINGERPRINT,
            "binary_sha256": {
                "archive_btxd": ARCHIVE_BTXD_SHA256,
                "archive_btx_cli": ARCHIVE_CLI_SHA256,
                "mirror_btxd": MIRROR_BTXD_SHA256,
                "mirror_btx_cli": MIRROR_CLI_SHA256,
            },
            "p2p_path": "local_loopback" if ARCHIVE_LOCAL else "ssh_local_forward",
            "activation_height": ACTIVATION,
            "archive_tip": tip,
            "mirror_tip": mirror_rpc("getbestblockhash"),
            "mirror_height": mirror_rpc("getblockcount"),
            "archive_services": a_services,
            "mirror_services": m_services,
            "mirror_mode": mirror_mode,
            "archive_trusted_status": archive_trusted,
            "trusted_status": trusted,
            "archive_production_canary": canary,
            "archive_last_validation": validation,
            "archive_strict_proof": strict_proof,
            "timings": timings,
            "activation_block_s": next(
                (t["archive_generate_s"] for t in timings if t["mined_height"] == ACTIVATION),
                None,
            ),
        }
        OUT.write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result, indent=2))
        print(f"WROTE {OUT}")
    finally:
        mirror_proc.terminate()
        try:
            mirror_proc.wait(timeout=30)
        except Exception:
            mirror_proc.kill()
        mirror_log.close()
        atexit.unregister(mirror_proc.terminate)
        if tunnel is not None:
            tunnel.terminate()
            try:
                tunnel.wait(timeout=10)
            except Exception:
                tunnel.kill()
            atexit.unregister(tunnel.terminate)
        cleanup_archive()
        if ARCHIVE_LOG is not None:
            ARCHIVE_LOG.close()
            ARCHIVE_LOG = None
        atexit.unregister(cleanup_archive)
        cleanup_local_artifacts()
        atexit.unregister(cleanup_local_artifacts)


if __name__ == "__main__":
    main()
