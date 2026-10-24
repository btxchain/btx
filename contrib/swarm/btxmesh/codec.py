"""Restricted canonical JSON: NFC strings, integers, no floats or duplicate keys.
Not advertised as RFC8785: arbitrary precision integers and NFC are intentional.
"""
import hashlib
import json
import math
import re
import unicodedata
from typing import Any
from .errors import require, MeshError

MAX_WIRE = 1024 * 1024
ID = re.compile(r"^[0-9a-f]{96}$")
ATOM_MAX = 21_000_000 * 100_000_000  # local exposure ceiling; not an issuance assertion

def check(value: Any, depth: int = 0):
    require(depth <= 32, "DEPTH")
    if value is None or type(value) is bool:
        return
    if type(value) is int:
        require(abs(value) < 2**127, "INTEGER_RANGE")
        return
    if isinstance(value, str):
        require(len(value) <= MAX_WIRE, "STRING_LIMIT")
        require(unicodedata.normalize("NFC", value) == value, "NONCANONICAL_STRING")
        require(not any(0xD800 <= ord(c) <= 0xDFFF for c in value), "UNICODE")
        return
    if isinstance(value, list):
        require(len(value) <= 16384, "ARRAY_LIMIT")
        for item in value:
            check(item, depth + 1)
        return
    if isinstance(value, dict):
        require(len(value) <= 256, "OBJECT_LIMIT")
        for k, v in value.items():
            require(isinstance(k, str), "KEY_TYPE")
            check(k, depth + 1); check(v, depth + 1)
        return
    raise MeshError("VALUE_TYPE", "Use integer fixed-point metrics or decimal strings, not floats")

def encode(value: Any, limit: int = MAX_WIRE) -> bytes:
    check(value)
    b = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()
    require(len(b) <= limit, "BODY_LIMIT")
    return b

def decode(data: bytes, limit: int = MAX_WIRE):
    require(len(data) <= limit, "BODY_LIMIT")
    def pairs(items):
        d = {}
        for k, v in items:
            require(k not in d, "DUPLICATE_KEY")
            d[k] = v
        return d
    try:
        obj = json.loads(data, object_pairs_hook=pairs)
    except (ValueError, UnicodeError) as e:
        raise MeshError("JSON", str(e)) from e
    check(obj)
    return obj

def digest(domain: str, obj: Any) -> str:
    return hashlib.sha384(domain.encode() + b"\x00" + encode(obj)).hexdigest()

def byte_id(data: bytes) -> str:
    return hashlib.sha384(data).hexdigest()

def fixed_id(value: str) -> str:
    require(isinstance(value, str) and ID.fullmatch(value) is not None, "ID")
    return value

def atoms(value: str) -> int:
    require(isinstance(value, str) and re.fullmatch(r"0|[1-9][0-9]{0,15}", value) is not None, "AMOUNT")
    n = int(value)
    require(n <= ATOM_MAX, "AMOUNT_RANGE")
    return n

def fields(obj: dict, required: set, optional: set = frozenset()):
    require(type(obj) is dict, "SCHEMA")
    require(required <= obj.keys() and obj.keys() <= required | optional, "SCHEMA", "missing or unknown field")

def integer(n, low: int, high: int, code="INTEGER"):
    require(type(n) is int and low <= n <= high, code)
    return n


def command_digest(command: dict) -> str:
    # Leader time and a retried transport envelope are not semantic command input.
    return digest("BTX/Command/1",{k:command[k] for k in ("kind","id","actor","body")})
