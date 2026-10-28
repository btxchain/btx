"""Bounded, duplicate-free JSON and domain-separated content identities.

This is a NeuronLab application namespace, NOT a replacement for BTX native IDs.
Signed records contain integers (usually millionths) rather than JSON floats.
"""
from __future__ import annotations
import hashlib
import json
import os
import re
import tempfile
import unicodedata
from pathlib import Path
from typing import Any

MAX_JSON = 1_048_576
MAX_DEPTH = 24
MAX_NODES = 50_000
ID_RE = re.compile(r"[0-9a-f]{96}\Z")

class LabError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
    def as_dict(self):
        return {"code": self.code, "message": str(self)}

def require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise LabError(code, message)

def keys(value: Any, required: set[str], optional: set[str] = frozenset()) -> dict:
    require(type(value) is dict, "SCHEMA", "Expected an object")
    require(required <= value.keys() and value.keys() <= required | optional,
            "SCHEMA", "Missing or unrecognized object fields")
    return value

def integer(value: Any, lo: int, hi: int, name: str = "integer") -> int:
    require(type(value) is int and lo <= value <= hi, "RANGE", f"Invalid {name}")
    return value

def text(value: Any, limit: int = 256, name: str = "text") -> str:
    require(type(value) is str and 0 < len(value.encode('utf-8')) <= limit,
            "TEXT", f"Invalid {name}")
    require(value == unicodedata.normalize('NFC', value) and
            not any(ord(c) < 32 or 0x7f <= ord(c) <= 0x9f or 0xd800 <= ord(c) <= 0xdfff for c in value),
            "TEXT", f"Noncanonical/control characters in {name}")
    return value

def digest_text(value: Any, name: str = "digest") -> str:
    require(type(value) is str and bool(ID_RE.fullmatch(value)), "DIGEST", f"Invalid {name}")
    return value

def _pairs(pairs):
    out = {}
    for k, v in pairs:
        require(k not in out, "DUPLICATE_KEY", "Duplicate JSON key")
        out[k] = v
    return out

def _bad_constant(_):
    raise LabError("NONFINITE", "Nonfinite JSON values are refused")

def bounded(value: Any, *, signed: bool = True) -> Any:
    work = [(value, 0)]
    count = 0
    while work:
        obj, depth = work.pop()
        count += 1
        require(depth <= MAX_DEPTH and count <= MAX_NODES, "BUDGET", "JSON structure exceeds budget")
        if type(obj) is dict:
            require(len(obj) <= 4096, "BUDGET", "Object too large")
            for k, v in obj.items():
                require(type(k) is str and k == unicodedata.normalize('NFC', k), "JSON_KEY", "Noncanonical key")
                require(not any(0xd800 <= ord(c) <= 0xdfff for c in k), "UNICODE", "Surrogate key")
                work.append((v, depth + 1))
        elif type(obj) is list:
            require(len(obj) <= 16384, "BUDGET", "Array too large")
            work.extend((v, depth + 1) for v in obj)
        elif type(obj) is str:
            require(len(obj.encode('utf-8', errors='surrogatepass')) <= MAX_JSON, "BUDGET", "String too large")
            require(obj == unicodedata.normalize('NFC', obj) and not any(0xd800 <= ord(c) <= 0xdfff for c in obj),
                    "UNICODE", "Noncanonical string")
        elif type(obj) is int:
            require(-(2**63) <= obj < 2**63, "INTEGER", "Integer exceeds signed 64-bit envelope")
        elif obj is None or type(obj) is bool:
            pass
        elif type(obj) is float and not signed:
            import math
            require(math.isfinite(obj), "NONFINITE", "Nonfinite number")
        else:
            raise LabError("JSON_TYPE", "Unsupported JSON type (signed records forbid floats)")
    return value

def loads(raw: str | bytes, *, signed: bool = True, limit: int = MAX_JSON) -> Any:
    b = raw.encode('utf-8') if isinstance(raw, str) else raw
    require(len(b) <= limit, "SIZE", "JSON exceeds byte limit")
    try:
        value = json.loads(b.decode('utf-8'), object_pairs_hook=_pairs, parse_constant=_bad_constant)
    except (UnicodeError, json.JSONDecodeError, RecursionError, OverflowError) as e:
        raise LabError("JSON", "Malformed JSON") from e
    return bounded(value, signed=signed)

def canonical(value: Any) -> bytes:
    bounded(value)
    raw = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode('utf-8')
    require(len(raw) <= MAX_JSON, "SIZE", "Canonical record exceeds byte limit")
    return raw

def identity(domain: str, value: Any) -> str:
    return hashlib.sha384(domain.encode('ascii') + b'\0' + canonical(value)).hexdigest()

def sha384(raw: bytes) -> str:
    return hashlib.sha384(raw).hexdigest()

def read_file(path: Path, limit: int) -> bytes:
    # O_NOFOLLOW protects the final component on Unix. Approved stores must also
    # remain private to the user; hostile same-user processes are outside the boundary.
    require(not path.is_symlink(), "SYMLINK", "Symlink files are refused")
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
    try:
        fd = os.open(path, flags)
        with os.fdopen(fd, 'rb') as f:
            import stat
            require(stat.S_ISREG(os.fstat(f.fileno()).st_mode), "FILE", "Regular file required")
            require(os.fstat(f.fileno()).st_size <= limit, "SIZE", "File exceeds limit")
            result = f.read(limit + 1)
            require(len(result) <= limit, "SIZE", "File grew beyond limit")
            return result
    except OSError as e:
        raise LabError("FILE", "Cannot read selected regular file") from e

def atomic_write(path: Path, raw: bytes, *, replace: bool = True) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    require(not path.is_symlink(), "SYMLINK", "Symlink destination refused")
    fd, name = tempfile.mkstemp(prefix='.pending-', dir=path.parent)
    try:
        os.chmod(name, 0o600)
        with os.fdopen(fd, 'wb') as f:
            f.write(raw)
            f.flush()
            os.fsync(f.fileno())
        if replace:
            os.replace(name, path)
        else:
            try:
                os.link(name, path)  # no-clobber publication
            except FileExistsError:
                raise LabError("EXISTS", "Destination already exists")
            os.unlink(name)
        if os.name == 'posix':
            dfd = os.open(path.parent, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
            try: os.fsync(dfd)
            finally: os.close(dfd)
    finally:
        try: os.unlink(name)
        except FileNotFoundError: pass
