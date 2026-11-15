"""SwapNet canonical JSON profile: ASCII keys, printable ASCII strings, no floats.

It is deliberately NOT advertised as general RFC 8785/JCS. Amounts are canonical
base-10 strings; integral metadata is bounded to the exact IEEE-754 integer range.
Network parsers reject duplicate names, non-finite numbers and deep structures.
"""
import hashlib
import json
import re
from .errors import SwapError, require

MAX_FRAME = 65536
MAX_DEPTH = 16
MAX_ITEMS = 4096
MAX_SAFE_INT = (1 << 53) - 1
MAX_ATOMS = (1 << 256) - 1
HEX32 = re.compile(r"[0-9a-f]{64}\Z")
DECIMAL = re.compile(r"(?:0|[1-9][0-9]{0,77})\Z")
KEY = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")

def atoms(value: str, *, positive=False) -> int:
    require(type(value) is str and DECIMAL.fullmatch(value) is not None,
            "AMOUNT_FORMAT", "Use a canonical decimal string of atomic units")
    n = int(value)
    require(n <= MAX_ATOMS and (not positive or n > 0), "AMOUNT_RANGE", "Amount out of range")
    return n

def integer(value, *, lo=0, hi=MAX_SAFE_INT):
    require(type(value) is int and lo <= value <= hi, "INTEGER_RANGE", "Invalid bounded integer")
    return value

def hex32(value: str) -> str:
    require(type(value) is str and HEX32.fullmatch(value) is not None, "HEX32", "Expected 32-byte lowercase hex")
    return value

def exact_fields(obj, required, optional=()):
    require(type(obj) is dict, "OBJECT", "Expected an object")
    keys = set(obj)
    require(set(required) <= keys <= set(required) | set(optional), "FIELDS", "Missing or unknown fields")

def _validate(value, depth=0, budget=None):
    if budget is None: budget = [MAX_ITEMS]
    budget[0] -= 1
    require(budget[0] >= 0 and depth <= MAX_DEPTH, "JSON_LIMIT", "JSON complexity limit exceeded")
    if value is None or type(value) is bool: return
    if type(value) is int:
        integer(value, lo=-MAX_SAFE_INT); return
    if type(value) is str:
        require(len(value) <= 32768 and all(32 <= ord(c) <= 126 for c in value),
                "JSON_STRING", "Only bounded printable ASCII strings are permitted")
        return
    if type(value) is list:
        for child in value: _validate(child, depth+1, budget)
        return
    if type(value) is dict:
        for key, child in value.items():
            require(type(key) is str and KEY.fullmatch(key) is not None, "JSON_KEY", "Invalid field name")
            _validate(child, depth+1, budget)
        return
    raise SwapError("JSON_TYPE", "Unsupported JSON type; floats are forbidden")

def dumps(value) -> bytes:
    _validate(value)
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")
    require(len(raw) <= MAX_FRAME, "FRAME_LIMIT", "Message exceeds limit")
    return raw

def _pairs(pairs):
    obj = {}
    for key, value in pairs:
        require(key not in obj, "DUPLICATE_KEY", "Duplicate JSON field")
        obj[key] = value
    return obj

def loads(raw):
    if type(raw) is str: raw = raw.encode("utf-8")
    require(type(raw) is bytes and len(raw) <= MAX_FRAME, "FRAME_LIMIT", "Message exceeds limit")
    try:
        obj = json.loads(raw.decode("ascii"), object_pairs_hook=_pairs,
                         parse_float=lambda _: (_ for _ in ()).throw(SwapError("FLOAT", "Float forbidden")),
                         parse_constant=lambda _: (_ for _ in ()).throw(SwapError("FLOAT", "Non-finite number forbidden")))
        _validate(obj)
        return obj
    except (UnicodeError, ValueError, RecursionError) as e:
        raise SwapError("JSON_INVALID", "Invalid encoded JSON") from e

def digest(domain: str, value) -> str:
    require(re.fullmatch(r"[A-Z0-9/_-]{1,64}", domain) is not None, "DOMAIN", "Invalid digest domain")
    return hashlib.sha256(domain.encode("ascii") + b"\x00" + dumps(value)).hexdigest()

def hashlock(secret: bytes) -> str:
    require(type(secret) is bytes and len(secret) == 32, "PREIMAGE_LENGTH", "Preimage must be 32 bytes")
    return hashlib.sha256(secret).hexdigest()
