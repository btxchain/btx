#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see COPYING.
"""Bounded process execution and content-bound evidence primitives.

An exit code is not a qualification. Commands, binaries, source trees, native
observations, and assertion plans are bound into a receipt by the orchestrator.
Receipts are authenticated with an operator-local HMAC key; that authenticates
the recording authority, not the truthfulness of an arbitrary test program.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
import platform
import re
import signal
import stat
import subprocess
import tempfile
import time
from typing import Any

SCHEMA = "BTX-NATIVE-EVIDENCE/1"
MAX_OUTPUT = 8 * 1024 * 1024
MAX_FILE = 8 * 1024 * 1024 * 1024
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
HEX40 = re.compile(r"[0-9a-f]{40}\Z")


class EvidenceError(ValueError):
    """A precondition or evidence-integrity check failed."""


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def sha256_file(path: Path, maximum: int = MAX_FILE) -> str:
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise EvidenceError(f"not a regular, non-symlink file: {path}")
    before = path.stat()
    if before.st_size > maximum:
        raise EvidenceError(f"file exceeds bound: {path}")
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            hasher.update(block)
    after = path.stat()
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
        raise EvidenceError(f"file changed during hashing: {path}")
    return hasher.hexdigest()


def strict_json(raw: bytes | str) -> Any:
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise EvidenceError(f"duplicate JSON key: {key}")
            result[key] = value
        return result
    try:
        return json.loads(raw, object_pairs_hook=unique,
                          parse_constant=lambda _: (_ for _ in ()).throw(EvidenceError("nonfinite JSON")))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EvidenceError(f"invalid JSON: {exc}") from exc


def atomic_json(path: Path, value: Any) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise EvidenceError("output may not be a symlink")
    fd, temporary = tempfile.mkstemp(prefix=".native-evidence-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(canonical(value) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def load_key(path: Path) -> bytes:
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise EvidenceError("key must be a regular file")
    mode = stat.S_IMODE(path.stat().st_mode)
    if os.name != "nt" and mode & 0o077:
        raise EvidenceError("key permissions must exclude group and other users")
    key = path.read_bytes()
    if len(key) != 32:
        raise EvidenceError("receipt key must contain exactly 32 random bytes")
    return key


def sign_receipt(body: dict, key: bytes) -> dict:
    return {"body": body, "hmac_sha256": hmac.new(key, canonical(body), hashlib.sha256).hexdigest()}


def verify_receipt(receipt: dict, key: bytes) -> dict:
    if set(receipt) != {"body", "hmac_sha256"}:
        raise EvidenceError("invalid receipt envelope")
    expected = hmac.new(key, canonical(receipt["body"]), hashlib.sha256).hexdigest()
    if not isinstance(receipt["hmac_sha256"], str) or not hmac.compare_digest(expected, receipt["hmac_sha256"]):
        raise EvidenceError("receipt authentication failed")
    return receipt["body"]


def _terminate(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    if os.name == "posix":
        os.killpg(process.pid, signal.SIGTERM)
    else:
        process.terminate()
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGKILL)
        else:
            process.kill()
        process.wait(timeout=5)


def run_command(argv: list[str], cwd: Path, timeout: int = 60,
                stdin: bytes | None = None, max_output: int = MAX_OUTPUT,
                env: dict[str, str] | None = None) -> dict:
    if not isinstance(argv, list) or not argv or any(not isinstance(x, str) or "\0" in x for x in argv):
        raise EvidenceError("argv must be a nonempty array of literal strings")
    if type(timeout) is not int or not 1 <= timeout <= 3600:
        raise EvidenceError("timeout must be 1..3600 seconds")
    if type(max_output) is not int or not 1024 <= max_output <= MAX_OUTPUT:
        raise EvidenceError("invalid output ceiling")
    # Never place RPC passwords or cloud credentials in the signed evidence.
    if any(re.search(r"(?i)(rpcpassword|authorization:|bearer |api[_-]?key=|secret=)", x) for x in argv):
        raise EvidenceError("credential-like command argument; use a cookie or protected file")
    started = time.time_ns()
    monotonic = time.monotonic()
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors, tempfile.TemporaryFile() as input_file:
        if stdin is not None:
            input_file.write(stdin)
            input_file.seek(0)
        process = subprocess.Popen(argv, cwd=str(cwd), stdin=input_file,
                                   stdout=output, stderr=errors, shell=False,
                                   env=env, start_new_session=(os.name == "posix"))
        failure = ""
        try:
            while process.poll() is None:
                if time.monotonic() - monotonic > timeout:
                    failure = "TIMEOUT"
                    break
                if os.fstat(output.fileno()).st_size + os.fstat(errors.fileno()).st_size > max_output:
                    failure = "OUTPUT_LIMIT"
                    break
                time.sleep(0.02)
        finally:
            if failure or process.poll() is None:
                _terminate(process)
        if os.fstat(output.fileno()).st_size + os.fstat(errors.fileno()).st_size > max_output:
            failure = "OUTPUT_LIMIT"
        output.seek(0)
        errors.seek(0)
        out = output.read(max_output)
        err = errors.read(max_output)
    return {"argv": argv, "started_ns": started, "finished_ns": time.time_ns(),
            "duration_ms": int((time.monotonic() - monotonic) * 1000),
            "returncode": process.returncode, "failure": failure,
            "stdout": out.decode("utf-8", errors="replace"),
            "stderr": err.decode("utf-8", errors="replace"),
            "stdout_sha256": hashlib.sha256(out).hexdigest(),
            "stderr_sha256": hashlib.sha256(err).hexdigest()}


def source_identity(root: Path) -> dict:
    root = Path(root).resolve(strict=True)
    commit = run_command(["git", "rev-parse", "HEAD"], root)
    if commit["returncode"] != 0 or not HEX40.fullmatch(commit["stdout"].strip()):
        raise EvidenceError("candidate must be a Git checkout with a pinned HEAD")
    files = run_command(["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], root)
    if files["returncode"] or files["failure"]:
        raise EvidenceError("cannot enumerate candidate source")
    names = sorted(set(name for name in files["stdout"].split("\0") if name))
    if len(names) > 100000:
        raise EvidenceError("source file bound exceeded")
    manifest = []
    for name in names:
        path = root / name
        if path.is_symlink():
            target = os.readlink(path)
            manifest.append({"path": name, "link": target})
        elif path.is_file():
            manifest.append({"path": name, "sha256": sha256_file(path, 256 * 1024 * 1024),
                             "executable": bool(path.stat().st_mode & 0o111)})
        else:
            # Deleted tracked source is part of this candidate, not silently ignored.
            manifest.append({"path": name, "missing": True})
    return {"commit": commit["stdout"].strip(), "source_tree_sha256": digest(manifest),
            "source_files": len(manifest)}


def machine_probe(root: Path, nonce: str) -> dict:
    if not HEX64.fullmatch(nonce):
        raise EvidenceError("probe challenge must be 256 random bits")
    identity_bytes = b""
    identity_source = "UNAVAILABLE"
    for filename in ("/sys/class/dmi/id/product_uuid", "/etc/machine-id", "/var/lib/dbus/machine-id"):
        try:
            raw = Path(filename).read_bytes().strip()
            if raw:
                identity_bytes, identity_source = raw, filename
                break
        except OSError:
            pass
    if platform.system() == "Darwin":
        observed = run_command(["/usr/sbin/ioreg", "-rd1", "-c", "IOPlatformExpertDevice"], root, 10)
        match = re.search(r'"IOPlatformUUID"\s*=\s*"([^"]+)"', observed["stdout"])
        if match:
            identity_bytes, identity_source = match.group(1).encode(), "IOPlatformUUID"
    elif platform.system() == "Windows":
        observed = run_command(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
                                "(Get-CimInstance Win32_ComputerSystemProduct).UUID"], root, 15)
        if observed["returncode"] == 0 and observed["stdout"].strip():
            identity_bytes, identity_source = observed["stdout"].strip().encode(), "Win32_ComputerSystemProduct.UUID"
    import shutil
    gpus = []
    gpu_probe = {"status": "ABSENT"}
    executable = shutil.which("nvidia-smi")
    if executable:
        gpu_probe = run_command([executable, "--query-gpu=uuid,name,pci.bus_id,compute_cap", "--format=csv,noheader,nounits"], root, 15)
        if not gpu_probe["failure"] and gpu_probe["returncode"] == 0:
            for line in gpu_probe["stdout"].splitlines():
                fields = [field.strip() for field in line.split(",")]
                if len(fields) == 4 and fields[0].startswith("GPU-"):
                    gpus.append(dict(zip(("uuid", "name", "pci_bus_id", "compute_capability"), fields)))
    npus, npu_probe = [], {"status": "ABSENT"}
    npu_executable = shutil.which("npu-smi")
    if npu_executable:
        listed = run_command([npu_executable, "info", "-l"], root, 15)
        npu_probe = {"list": listed, "boards": []}
        # Ascend's published npu-smi interface uses info -l for NPU IDs and
        # info -t board -i ID for board serials. Containers that hide serials
        # remain unqualified rather than receiving invented device identities.
        device_ids = sorted(set(re.findall(r"NPU\s+ID\s*:\s*(\d+)", listed["stdout"])))[:32]
        if listed["returncode"] == 0 and not listed["failure"]:
            for device_id in device_ids:
                board = run_command([npu_executable, "info", "-t", "board", "-i", device_id], root, 15)
                npu_probe["boards"].append(board)
                serial = re.search(r"Serial\s+Number\s*:\s*([^\r\n]+)", board["stdout"])
                if board["returncode"] == 0 and not board["failure"] and serial:
                    identifier = serial.group(1).strip()
                    if identifier and identifier.upper() not in {"NA", "N/A", "UNKNOWN", "NONE"}:
                        npus.append({"device_id": device_id,
                                     "serial_sha256": hashlib.sha256(b"BTX/ASCEND-BOARD/1\0" + identifier.encode()).hexdigest()})
    return {"nonce": nonce, "source": source_identity(root), "system": platform.system(),
            "architecture": platform.machine(), "python": platform.python_version(),
            "machine_id_sha256": hashlib.sha256(b"BTX/NATIVE-MACHINE/1\0" + identity_bytes).hexdigest() if identity_bytes else None,
            "identity_source": identity_source, "gpus": gpus, "gpu_probe": gpu_probe,
            "npus": npus, "npu_probe": npu_probe,
            "identity_limit": "OS/firmware identity; not hardware-root attestation and not proof of distinct physical chassis"}


def json_path(value: Any, path: str) -> Any:
    if not isinstance(path, str) or not path:
        raise EvidenceError("JSON assertion path is required")
    for part in path.split("."):
        if isinstance(value, dict) and part in value:
            value = value[part]
        elif isinstance(value, list) and part.isdigit() and int(part) < len(value):
            value = value[int(part)]
        else:
            raise EvidenceError(f"observation missing: {path}")
    return value


def evaluate_assertions(observation: Any, assertions: list[dict]) -> list[dict]:
    if not isinstance(assertions, list) or not assertions:
        raise EvidenceError("a native test requires observed-output assertions")
    outcomes = []
    for assertion in assertions:
        if not isinstance(assertion, dict) or set(assertion) - {"path", "op", "value"}:
            raise EvidenceError("invalid assertion")
        value = json_path(observation, assertion.get("path", ""))
        op, expected = assertion.get("op"), assertion.get("value")
        if op == "eq":
            passed = type(value) is type(expected) and value == expected
        elif op == "ne":
            passed = type(value) is not type(expected) or value != expected
        elif op == "min":
            passed = type(value) in (int, float) and type(expected) in (int, float) and value >= expected
        elif op == "nonempty":
            passed = isinstance(value, (str, list, dict)) and len(value) > 0
        elif op == "sha256":
            passed = isinstance(value, str) and bool(HEX64.fullmatch(value))
        elif op == "contains":
            passed = isinstance(value, (str, list)) and expected in value
        elif op == "unique_count":
            passed = isinstance(value, list) and type(expected) is int and len({canonical(v) for v in value}) >= expected
        else:
            raise EvidenceError(f"unsupported assertion operator: {op}")
        outcomes.append({"assertion": assertion, "observed": value, "passed": bool(passed)})
    return outcomes
