"""Reference-only HCP structural checks. No native crypto, consensus or execution.

Use native BTX-PJSON1/ML-DSA implementation for production conformance. This
reader is independently useful for negative vectors, not a trust verifier.
"""
from __future__ import annotations
import hashlib, json, re, struct
from typing import Any

MAX_BODY = 1_048_576
MAX_DEPTH = 32
MAX_NODES = 65_536
MAX_SAFE_INT = 2**53-1

class ContractError(ValueError):
    pass

def _no_float(value: str) -> None:
    raise ContractError('FLOAT_NOT_CANONICAL')

def _integer(value: str) -> int:
    if value == '-0': raise ContractError('NEGATIVE_ZERO')
    n = int(value)
    if abs(n) > MAX_SAFE_INT: raise ContractError('INTEGER_RANGE')
    return n

def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for k,v in pairs:
        if k in result: raise ContractError('DUPLICATE_KEY')
        result[k]=v
    return result

def canonical_body(value: Any) -> bytes:
    count=0
    def visit(v: Any, depth: int=0) -> None:
        nonlocal count
        count += 1
        if count > MAX_NODES or depth > MAX_DEPTH: raise ContractError('STRUCTURAL_LIMIT')
        if v is None or isinstance(v, bool): return
        if isinstance(v,int):
            if abs(v)>MAX_SAFE_INT: raise ContractError('INTEGER_RANGE')
            return
        if isinstance(v,str):
            try:v.encode('utf-8','strict')
            except UnicodeError as e:raise ContractError('UTF8_INVALID') from e
            return
        if isinstance(v,list):
            for x in v: visit(x,depth+1)
            return
        if isinstance(v,dict):
            for k,x in v.items():
                if not isinstance(k,str) or not k.isascii(): raise ContractError('SCHEMA_KEY_INVALID')
                if any(ord(c)<32 for c in k): raise ContractError('SCHEMA_KEY_INVALID')
                visit(x,depth+1)
            return
        raise ContractError('UNSUPPORTED_JSON_TYPE')
    visit(value)
    raw=json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode('utf-8')
    if len(raw)>MAX_BODY:raise ContractError('BODY_TOO_LARGE')
    return raw

def parse_canonical(raw: bytes) -> Any:
    if len(raw)>MAX_BODY:raise ContractError('BODY_TOO_LARGE')
    try:
        value=json.loads(raw.decode('utf-8','strict'),object_pairs_hook=_pairs,
            parse_float=_no_float,parse_constant=_no_float,parse_int=_integer)
    except (ValueError,UnicodeError,RecursionError) as e:
        raise ContractError(str(e)) from e
    if canonical_body(value)!=raw:raise ContractError('NONCANONICAL_BYTES')
    return value

def body_id(kind: str, value: dict[str,Any]) -> str:
    if not re.fullmatch(r'[A-Za-z][A-Za-z0-9]{0,63}',kind):raise ContractError('OBJECT_TYPE')
    b=canonical_body(value)
    return hashlib.sha384(f'BTX/HCP/{kind}/v1'.encode()+b'\0'+struct.pack('<Q',len(b))+b).hexdigest()

def check_integrity(envelope: dict[str, Any]) -> dict[str, Any]:
    if body_id(envelope['object_type'],envelope['body'])!=envelope['body_id']:
        raise ContractError('BODY_ID_MISMATCH')
    return {'body_integrity':True,'signature_verified':False,'trust_established':False,
            'reason':'REFERENCE_CHECK_ONLY'}

def atoms(value: str, maximum: int=2**63-1) -> int:
    if not isinstance(value,str) or not re.fullmatch(r'0|[1-9][0-9]{0,19}',value):
        raise ContractError('ATOM_ENCODING')
    n=int(value)
    if n>maximum:raise ContractError('AMOUNT_RANGE')
    return n

def validate_amounts(a: dict[str,str]) -> int:
    total=sum(atoms(a[k]) for k in ['principal_atoms','network_fee_cap_atoms','service_fee_atoms','tax_atoms'])
    if total!=atoms(a['max_total_debit_atoms']):raise ContractError('TOTAL_MISMATCH')
    return total

def check_handoff_bindings(body: dict[str, Any], *, provider_id: str, account: str,
                           device: str, nonce: str, now_ms: int,
                           package_core_id: str, recipe_id: str,
                           local_effects: set[str]) -> dict[str, Any]:
    """Assumes no signature trust. Checks only bindings and local effects in fixture."""
    for k,v in [('provider_id',provider_id),('account_ref',account),('device_id',device),('request_nonce',nonce)]:
        if body[k]!=v:raise ContractError('HANDOFF_BINDING')
    if atoms(body['expires_at_ms'])<=now_ms:raise ContractError('HANDOFF_EXPIRED')
    if atoms(body['issued_at_ms'])>now_ms:raise ContractError('HANDOFF_NOT_YET_VALID')
    if body['package']['package_core_id']!=package_core_id or body['package']['recipe_id']!=recipe_id:
        raise ContractError('PACKAGE_MISMATCH')
    if not set(body['requested_effects']).issubset(local_effects):raise ContractError('LOCAL_GRANT_REQUIRED')
    return {'bindings_match':True,'ready':False,'production_trust':'NOT_CHECKED'}
