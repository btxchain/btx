#!/usr/bin/env python3
"""Two-node trusted-mirror rehearsal: GPU archive + CPU mirror.

Archive runs matmulvalidation=consensus with attestation signing/serving.
Mirror runs matmulvalidation=trusted and accepts Profile-1 ExactReplay via
signed quorum from the archive — no local GPU required.

Usage (run on the non-GPU host):

  python3 -u contrib/matmul-v4/two-node-trusted-mirror-rehearsal.py \\
    --archive-host gpu-archive.example.invalid \\
    --archive-user operator \\
    --archive-btxd /path/to/gpu-build/bin/btxd \\
    --archive-cli /path/to/gpu-build/bin/btx-cli \\
    --mirror-btxd /path/to/cpu-build/bin/btxd \\
    --mirror-cli /path/to/cpu-build/bin/btx-cli \\
    --source-revision <exact-40-character-commit> \\
    --archive-btxd-sha256 <reviewed-sha256> \\
    --archive-cli-sha256 <reviewed-sha256> \\
    --mirror-btxd-sha256 <reviewed-sha256> \\
    --mirror-cli-sha256 <reviewed-sha256> \\
    --signer-wif-file /secure/path/to/signer.wif \\
    --signer-pub-file /secure/path/to/signer.pub

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
MIRROR_BTXD = Path()
MIRROR_CLI = Path()
SIGNER_WIF_FILE = Path()
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
REPO_ROOT = Path(__file__).resolve().parents[2]
SOURCE_REVISION = ""
SOURCE_TREE_FINGERPRINT = ""
ARCHIVE_BTXD_SHA256 = ""
ARCHIVE_CLI_SHA256 = ""
MIRROR_BTXD_SHA256 = ""
MIRROR_CLI_SHA256 = ""
REMOTE_ARCHIVE_NAME = re.compile(r"btx-trusted-archive\.[A-Za-z0-9]{6}")
COMPRESSED_PUBKEY = re.compile(r"(?:02|03)[0-9a-fA-F]{64}")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive-host", default=os.environ.get("ARCHIVE_HOST"))
    parser.add_argument("--archive-user", default=os.environ.get("ARCHIVE_USER"))
    parser.add_argument("--archive-btxd", default=os.environ.get("ARCHIVE_BTXD"))
    parser.add_argument("--archive-cli", default=os.environ.get("ARCHIVE_CLI"))
    parser.add_argument("--mirror-btxd", type=Path, default=os.environ.get("MIRROR_BTXD"))
    parser.add_argument("--mirror-cli", type=Path, default=os.environ.get("MIRROR_CLI"))
    parser.add_argument(
        "--signer-wif-file", type=Path, default=os.environ.get("SIGNER_WIF_FILE")
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
        ("archive_host", "--archive-host", "ARCHIVE_HOST"),
        ("archive_user", "--archive-user", "ARCHIVE_USER"),
        ("archive_btxd", "--archive-btxd", "ARCHIVE_BTXD"),
        ("archive_cli", "--archive-cli", "ARCHIVE_CLI"),
        ("mirror_btxd", "--mirror-btxd", "MIRROR_BTXD"),
        ("mirror_cli", "--mirror-cli", "MIRROR_CLI"),
        ("signer_wif_file", "--signer-wif-file", "SIGNER_WIF_FILE"),
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
    for name, option in (
        ("mirror_btxd", "--mirror-btxd"),
        ("mirror_cli", "--mirror-cli"),
        ("signer_wif_file", "--signer-wif-file"),
        ("signer_pub_file", "--signer-pub-file"),
    ):
        path = getattr(args, name)
        if not path.is_file():
            parser.error(f"{option} is not a file: {path}")
    if not args.runtime_root.is_dir():
        parser.error(f"--runtime-root is not a directory: {args.runtime_root}")
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


def cleanup_remote_archive() -> None:
    if not ARCHIVE_DD:
        return
    try:
        sh_remote(
            f"kill $(cat {shlex.quote(ARCHIVE_DD + '/regtest/btxd.pid')} "
            "2>/dev/null) 2>/dev/null || true"
        )
    except Exception:
        pass
    try:
        sh_remote(f"rm -f -- {shlex.quote(ARCHIVE_DD + '/regtest/signer.wif')}")
    except Exception:
        pass
    if not KEEP_ARTIFACTS:
        try:
            sh_remote(f"rm -rf -- {shlex.quote(ARCHIVE_DD)}")
        except Exception:
            pass


def _require_object(parent: dict, key: str, path: str) -> dict:
    value = parent.get(key)
    if not isinstance(value, dict):
        raise RuntimeError(f"getmininginfo schema error: {path} must be an object")
    return value


def extract_strict_replay_evidence(
    mining_info: object, *, expected_revision: str | None = None,
    expected_fingerprint: str | None = None,
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
    for obj, key, expected, path in (
        (canary, "passed", bool, "production_canary.passed"),
        (canary, "device_macs", int, "production_canary.device_macs"),
        (canary, "cpu_fallbacks", int, "production_canary.cpu_fallbacks"),
        (validation, "available", bool, "last_validation.available"),
        (validation, "require_device", bool, "last_validation.require_device"),
        (validation, "fully_accelerated", bool, "last_validation.fully_accelerated"),
        (validation, "cpu_gemm_calls", int, "last_validation.cpu_gemm_calls"),
        (validation, "cpu_gemm_fallbacks", int, "last_validation.cpu_gemm_fallbacks"),
    ):
        value = obj.get(key)
        if not isinstance(value, expected) or (
            expected is int and (isinstance(value, bool) or value < 0)
        ):
            typename = "a non-negative integer" if expected is int else "a boolean"
            raise RuntimeError(f"getmininginfo schema error: {path} must be {typename}")
    if not isinstance(validation.get("provider"), str) or not validation["provider"]:
        raise RuntimeError(
            "getmininginfo schema error: last_validation.provider must be a non-empty string"
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


def main(argv: list[str] | None = None) -> None:
    global ARCHIVE_DD, ARCHIVE_HOST, ARCHIVE_USER, ARCHIVE_BTXD, ARCHIVE_CLI
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
    try:
        if remote_sha256(ARCHIVE_BTXD) != ARCHIVE_BTXD_SHA256:
            parser.error("archive btxd SHA256 does not match --archive-btxd-sha256")
        if remote_sha256(ARCHIVE_CLI) != ARCHIVE_CLI_SHA256:
            parser.error("archive btx-cli SHA256 does not match --archive-cli-sha256")
    except (subprocess.SubprocessError, EVIDENCE_IDENTITY.EvidenceIdentityError) as error:
        parser.error(f"cannot verify archive binary identity: {error}")
    MIRROR_DD = Path(
        tempfile.mkdtemp(prefix="btx-trusted-mirror-", dir=RUNTIME_ROOT)
    )
    atexit.register(cleanup_local_artifacts)

    ARCHIVE_DD = validate_remote_archive_dir(
        sh_remote("mktemp -d \"${TMPDIR:-/tmp}/btx-trusted-archive.XXXXXX\"")
    )
    atexit.register(cleanup_remote_archive)
    archive_regtest = f"{ARCHIVE_DD}/regtest"
    sh_remote(f"umask 077; mkdir -p {shlex.quote(archive_regtest)}")
    signer_wif = SIGNER_WIF_FILE.read_text().strip() + "\n"
    sh_remote(
        f"umask 077; cat > {shlex.quote(archive_regtest + '/signer.wif')}",
        input_text=signer_wif,
    )
    del signer_wif

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
matmulattestationsignerkeyfile=signer.wif
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
    # Write archive conf remotely
    sh_remote(
        f"umask 077; cat > {shlex.quote(ARCHIVE_DD + '/btx.conf')}",
        input_text=archive_conf,
    )

    # SSH local forward so this host reaches archive P2P on loopback
    # (LAN P2P may be firewalled; RPC stays via ssh command).
    tunnel = subprocess.Popen(
        [
            "ssh",
            "-o",
            "BatchMode=yes",
            "-N",
            "-L",
            f"127.0.0.1:{ARCHIVE_P2P}:127.0.0.1:{ARCHIVE_P2P}",
            f"{ARCHIVE_USER}@{ARCHIVE_HOST}",
        ]
    )
    atexit.register(tunnel.terminate)
    time.sleep(1)

    mirror_conf = common_regtest + f"""
matmulvalidation=trusted
matmulrcexecution=strict-device
matmulattestationserve=0
listenonion=0
[regtest]
port={MIRROR_P2P}
rpcport={MIRROR_RPC}
connect=127.0.0.1:{ARCHIVE_P2P}
"""
    (MIRROR_DD / "btx.conf").write_text(mirror_conf)

    # Start archive on GPU host
    sh_remote(
        f"CUDA_VISIBLE_DEVICES=0 nohup {shlex.quote(ARCHIVE_BTXD)} "
        f"-datadir={shlex.quote(ARCHIVE_DD)} "
        f"-conf={shlex.quote(ARCHIVE_DD + '/btx.conf')} "
        f">{shlex.quote(ARCHIVE_DD + '/stdout.log')} 2>&1 & echo $!"
    )
    wait_rpc(archive_rpc, "archive")
    archive_rpc("createwallet", "miner")

    # Start local mirror
    mirror_log = (MIRROR_DD / "stdout.log").open("w")
    mirror_proc = subprocess.Popen(
        [str(MIRROR_BTXD), f"-datadir={MIRROR_DD}", f"-conf={MIRROR_DD / 'btx.conf'}"],
        stdout=mirror_log,
        stderr=subprocess.STDOUT,
    )
    atexit.register(mirror_proc.terminate)
    try:
        wait_rpc(mirror_rpc, "mirror")
        # Wait until P2P link is up through the tunnel
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            peers = mirror_rpc("getpeerinfo") or []
            if peers:
                print(f"mirror peers={[p.get('addr') for p in peers]}", flush=True)
                break
            time.sleep(1)
        else:
            raise RuntimeError("mirror never connected to archive P2P via tunnel")

        a_net = archive_rpc("getnetworkinfo")
        m_net = mirror_rpc("getnetworkinfo")
        a_services = a_net.get("localservicesnames", [])
        m_services = m_net.get("localservicesnames", [])
        print("archive_services", a_services, flush=True)
        print("mirror_services", m_services, flush=True)

        # Mine through activation+2 on archive; mirror should follow via attestations
        timings = []
        for _ in range(ACTIVATION + 2):
            t0 = time.perf_counter()
            archive_rpc("generatetoaddress", "1", archive_rpc("getnewaddress"))
            dt = time.perf_counter() - t0
            ah = archive_rpc("getblockcount")
            timings.append({"mined_height": ah, "archive_generate_s": round(dt, 3)})
            print(f"archive mined h={ah} in {dt:.3f}s", flush=True)

        tip = archive_rpc("getbestblockhash")
        deadline = time.monotonic() + 300
        while time.monotonic() < deadline:
            if mirror_rpc("getbestblockhash") == tip:
                break
            time.sleep(1)
        else:
            raise RuntimeError(
                "mirror did not catch tip; trusted="
                + json.dumps(mirror_rpc("getmatmultrustedstatus"))
            )

        trusted = mirror_rpc("getmatmultrustedstatus")
        archive_rc, canary, validation = extract_strict_replay_evidence(
            archive_rpc("getmininginfo"),
            expected_revision=SOURCE_REVISION,
            expected_fingerprint=SOURCE_TREE_FINGERPRINT,
        )
        if not (
            canary.get("passed")
            and canary.get("device_macs", 0) > 0
            and canary.get("cpu_fallbacks") == 0
            and validation.get("available")
            and validation.get("require_device")
            and validation.get("fully_accelerated")
            and validation.get("cpu_gemm_calls") == 0
            and validation.get("cpu_gemm_fallbacks") == 0
        ):
            raise RuntimeError("archive did not prove strict zero-fallback ExactReplay")
        result = {
            "ok": True,
            "archive_host_class": "cuda_gpu_exactreplay_archive",
            "mirror_host_class": "cpu_trusted_mirror",
            "source_revision": SOURCE_REVISION,
            "source_tree_fingerprint": SOURCE_TREE_FINGERPRINT,
            "binary_sha256": {
                "archive_btxd": ARCHIVE_BTXD_SHA256,
                "archive_btx_cli": ARCHIVE_CLI_SHA256,
                "mirror_btxd": MIRROR_BTXD_SHA256,
                "mirror_btx_cli": MIRROR_CLI_SHA256,
            },
            "p2p_path": "ssh_local_forward",
            "activation_height": ACTIVATION,
            "archive_tip": tip,
            "mirror_tip": mirror_rpc("getbestblockhash"),
            "mirror_height": mirror_rpc("getblockcount"),
            "archive_services": a_services,
            "mirror_services": m_services,
            "mirror_mode": mirror_rpc("getblockchaininfo").get("matmulvalidationmode"),
            "trusted_status": trusted,
            "archive_production_canary": canary,
            "archive_last_validation": validation,
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
        atexit.unregister(mirror_proc.terminate)
        tunnel.terminate()
        try:
            tunnel.wait(timeout=10)
        except Exception:
            tunnel.kill()
        atexit.unregister(tunnel.terminate)
        cleanup_remote_archive()
        atexit.unregister(cleanup_remote_archive)
        cleanup_local_artifacts()
        atexit.unregister(cleanup_local_artifacts)


if __name__ == "__main__":
    main()
