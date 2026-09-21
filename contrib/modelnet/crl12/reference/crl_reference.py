"""Executable CRL/1.2 reference semantics; not a signer, custodian or node.

These functions model bounded validation, temporal selection and reporting.
Production authority, database transactions, chain verification and ML-DSA
must use the actual BTX/HCP implementations specified in the document set.
"""
from __future__ import annotations
from dataclasses import dataclass, replace
from decimal import Decimal, localcontext, ROUND_HALF_EVEN
import hashlib
import json
import re
import struct
from typing import Any, Iterable, Mapping

MAX_JSON_INTEGER = (1 << 53) - 1
TYPES = frozenset((
    'LayerExtensionProfileV1_2', 'ProviderRoleManifestV1_2', 'ServiceBindingV1_2',
    'AdapterCapabilityManifestV1_2', 'InstitutionalAssetRecordV1_2',
    'RightsStatementV1_2', 'PositionObservationV1_2', 'ValuationObservationV1_2',
    'ExposureLinkV1_2', 'PortfolioProjectionV1_2', 'MetricDefinitionV1_2',
    'ExportManifestV1_2', 'PortfolioInstructionV1_2', 'InteroperabilityReceiptV1_2',
    'ScenarioDefinitionV1_2', 'ScenarioResultV1_2', 'ConformanceStatementV1_2',
    'ReconciliationBreakV1_2',
))
ROLES = frozenset(('DISCOVERY','CUSTODY','EXECUTION','FUNDING','TREASURY',
                  'DEVICE_HANDOFF','ASSET_SERVICING','PORTFOLIO_ANALYTICS','FIAT_RAIL'))

class ContractError(ValueError):
    """Stable error code from reference validation."""

def uint(value: str, maximum: int = (1 << 64) - 1) -> int:
    if not isinstance(value, str) or not re.fullmatch(r'0|[1-9][0-9]{0,76}', value):
        raise ContractError('NONCANONICAL_INTEGER')
    result = int(value)
    if result > maximum:
        raise ContractError('INTEGER_RANGE')
    return result

def _walk(value: Any, depth: int = 0, counter: list[int] | None = None) -> None:
    counter = [0] if counter is None else counter
    counter[0] += 1
    if depth > 32 or counter[0] > 65536:
        raise ContractError('JSON_LIMIT')
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int):
        if abs(value) > MAX_JSON_INTEGER:
            raise ContractError('JSON_INTEGER_RANGE')
    elif isinstance(value, str):
        try:
            value.encode('utf-8', 'strict')
        except UnicodeError as e:
            raise ContractError('INVALID_UTF8') from e
    elif isinstance(value, list):
        for item in value:
            _walk(item, depth+1, counter)
    elif isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str) or not key.isascii() or any(ord(c)<32 for c in key):
                raise ContractError('INVALID_KEY')
            _walk(item, depth+1, counter)
    else:
        raise ContractError('UNSUPPORTED_JSON_TYPE')

def canonical_json(value: Any) -> bytes:
    _walk(value)
    return json.dumps(value, sort_keys=True, ensure_ascii=False,
                      separators=(',', ':'), allow_nan=False).encode('utf-8')

def parse_canonical(raw: bytes) -> Any:
    if len(raw) > 1048576:
        raise ContractError('BODY_TOO_LARGE')
    def pairs(rows: list[tuple[str, Any]]) -> dict[str, Any]:
        d: dict[str, Any] = {}
        for k,v in rows:
            if k in d:
                raise ContractError('DUPLICATE_KEY')
            d[k] = v
        return d
    def integer(s: str) -> int:
        if s == '-0':
            raise ContractError('NEGATIVE_ZERO')
        return int(s)
    def no_float(s: str) -> None:
        raise ContractError('FLOAT_FORBIDDEN')
    try:
        decoded = json.loads(raw.decode('utf-8'), object_pairs_hook=pairs,
                             parse_int=integer, parse_float=no_float, parse_constant=no_float)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as e:
        raise ContractError('INVALID_JSON') from e
    if canonical_json(decoded) != raw:
        raise ContractError('NONCANONICAL_JSON')
    return decoded

def body_id(object_type: str, body: Mapping[str, Any]) -> str:
    if object_type not in TYPES:
        raise ContractError('UNKNOWN_OBJECT_TYPE')
    data = canonical_json(dict(body))
    return hashlib.sha384(('BTX/HCP/'+object_type+'/v1').encode()+b'\0'+
                          struct.pack('<Q',len(data))+data).hexdigest()

def validate_role_operations(roles: Iterable[str], advertised: Mapping[str,str],
                             registry: Mapping[str,str]) -> None:
    requested = list(roles)
    if not requested or len(requested) != len(set(requested)) or not set(requested) <= ROLES:
        raise ContractError('ROLE_UNAVAILABLE')
    for operation, effect in advertised.items():
        if registry.get(operation) != effect:
            raise ContractError('ROLE_EFFECT_MISMATCH')

def check_binding(*, role: str, offered_roles: set[str], requested_effect: str,
                  permitted_effects: set[str], owner_effects: set[str],
                  active: bool, expires: int, now: int, network_matches: bool) -> None:
    if not active or now >= expires:
        raise ContractError('BINDING_REVOKED')
    if role not in offered_roles or not network_matches:
        raise ContractError('ROLE_UNAVAILABLE')
    if requested_effect not in permitted_effects & owner_effects:
        raise ContractError('EFFECT_DENIED')

@dataclass(frozen=True)
class Observation:
    entity: str
    position: str
    source: str
    generation: str
    sequence: int
    effective: int
    recorded: int
    quantity: int
    digest: str
    status: str = 'OPEN'

def select_asof(records: Iterable[Observation], *, entity: str, as_of: int,
                cutoff: int, authoritative_sources: Mapping[str,str]) -> list[Observation]:
    seen: dict[tuple[str,str,str,int], str] = {}
    candidates: dict[str, Observation] = {}
    for r in records:
        if r.entity != entity or r.recorded > cutoff:
            continue
        k = (r.source,r.generation,r.position,r.sequence)
        if k in seen and seen[k] != r.digest:
            raise ContractError('OBSERVATION_CONFLICT')
        seen[k] = r.digest
        if r.recorded > cutoff or r.effective > as_of:
            continue
        if authoritative_sources.get(r.position) != r.source:
            continue
        if r.sequence < 0 or r.quantity < 0:
            raise ContractError('QUANTITY_RANGE')
        previous = candidates.get(r.position)
        if previous and previous.generation != r.generation:
            raise ContractError('GENERATION_RECONCILIATION_REQUIRED')
        if previous is None or r.sequence > previous.sequence:
            candidates[r.position] = r
    if any(r.status == 'DISPUTED' for r in candidates.values()):
        raise ContractError('RECONCILIATION_REQUIRED')
    return sorted((r for r in candidates.values() if r.status == 'OPEN'), key=lambda x:x.position)

@dataclass(frozen=True)
class MetricPosition:
    key: str
    asset_kind: str
    financial: bool
    view: str
    currency: str
    exponent: int
    value_minor: int | None
    purpose: str = 'MARKET_VALUE'
    current: bool = True
    managed: bool = False
    custodied: bool = False
    administered: bool = False

def metric(positions: Iterable[MetricPosition], *, kind: str, currency: str,
           exponent: int, coverage_complete: bool = True) -> dict[str, Any]:
    if kind not in {'AUM','AUC','AUA','FINANCIAL_NAV','CAPABILITY_COUNT','ACTUAL_COST'}:
        raise ContractError('METRIC_UNSUPPORTED')
    unique: dict[str, MetricPosition] = {}
    for p in positions:
        if p.key in unique and unique[p.key] != p:
            raise ContractError('DUPLICATE_CLAIM')
        unique[p.key] = p
    values: list[int] = []
    eligible=unpriced=excluded=count=0
    for p in unique.values():
        if kind == 'CAPABILITY_COUNT':
            if p.asset_kind == 'CAPABILITY_RESOURCE' and p.view == 'OPERATIONAL':
                count+=1; eligible+=1
            else:
                excluded+=1
            continue
        if kind == 'ACTUAL_COST':
            ok = p.purpose == 'COST_BASIS'
        else:
            ok = p.financial and p.view == 'DIRECT' and p.purpose == 'MARKET_VALUE'
            ok = ok and (kind != 'AUM' or p.managed) and (kind != 'AUC' or p.custodied)
            ok = ok and (kind != 'AUA' or p.administered)
        if not ok:
            excluded+=1; continue
        eligible+=1
        if p.currency != currency or p.exponent != exponent:
            raise ContractError('CURRENCY_MAPPING_REQUIRED')
        if p.value_minor is None or not p.current:
            unpriced+=1
        else:
            values.append(p.value_minor)
    status = 'COMPLETE' if coverage_complete and unpriced == 0 else 'PARTIAL'
    value = sum(values) if values or (coverage_complete and eligible == 0) else None
    if kind == 'CAPABILITY_COUNT':
        return dict(value=None,count=count,status=status,eligible=eligible,unpriced=0,excluded=excluded)
    if value is None:
        status='UNAVAILABLE'
    return dict(value=value,count=None,status=status,eligible=eligible,unpriced=unpriced,excluded=excluded)

def convert_minor(value: int, source_exponent: int, rate: str, target_exponent: int) -> int:
    if not 0 <= source_exponent <= 18 or not 0 <= target_exponent <= 18:
        raise ContractError('EXPONENT_RANGE')
    with localcontext() as ctx:
        ctx.prec=160
        try:
            r=Decimal(rate)
        except Exception as e:
            raise ContractError('RATE_INVALID') from e
        if not r.is_finite() or r <= 0:
            raise ContractError('RATE_INVALID')
        amount=Decimal(value).scaleb(-source_exponent)*r
        return int(amount.scaleb(target_exponent).quantize(Decimal(1), rounding=ROUND_HALF_EVEN))

def expand_exposure(root: str, graph: Mapping[str,list[tuple[str,Decimal]]], *, max_depth: int=16) -> dict[str,Decimal]:
    out: dict[str,Decimal]={}
    visited_edges=0
    def walk(node: str, weight: Decimal, stack: tuple[str,...]) -> None:
        nonlocal visited_edges
        if node in stack:
            raise ContractError('LOOKTHROUGH_CYCLE')
        if len(stack)>max_depth:
            raise ContractError('GRAPH_LIMIT')
        children=graph.get(node)
        if not children:
            out[node]=out.get(node,Decimal(0))+weight; return
        if any(not w.is_finite() or w < 0 for _,w in children):
            raise ContractError('WEIGHT_RANGE')
        if len(children)>256 or sum((w for _,w in children),Decimal(0))>1:
            raise ContractError('WEIGHT_RANGE')
        total=Decimal(0)
        for child,w in children:
            if not w.is_finite() or w<0:
                raise ContractError('WEIGHT_RANGE')
            visited_edges+=1
            if visited_edges>65536:
                raise ContractError('GRAPH_LIMIT')
            total+=w
            walk(child,weight*w,stack+(node,))
        if total<1:
            key='unresolved:'+node
            out[key]=out.get(key,Decimal(0))+weight*(1-total)
    walk(root,Decimal(1),())
    return out

class IdempotencyStore:
    """In-memory reference only. Production uses shared durable uniqueness."""
    def __init__(self) -> None:
        self.rows: dict[tuple[str,str,str,str], tuple[str,Any]] = {}
    def record(self, provider: str, tenant: str, entity: str, operation: str,
               body_digest: str, result: Any) -> Any:
        key=(provider,tenant,entity,operation)
        if key in self.rows:
            old,r=self.rows[key]
            if old != body_digest:
                raise ContractError('IDEMPOTENCY_CONFLICT')
            return r
        self.rows[key]=(body_digest,result)
        return result

class ImportStore:
    """Quarantine/validate/commit model; never touches monetary balances."""
    def __init__(self) -> None:
        self.staged: dict[tuple[str,str],bytes]={}
        self.validated: dict[tuple[str,str],tuple[str,tuple[str,...]]]={}
        self.published: dict[tuple[str,str],str]={}
    def stage(self, tenant: str, chunk_id: str, content: bytes, expected: str) -> None:
        if not content or len(content)>16*1024*1024:
            raise ContractError('CHUNK_LIMIT')
        if hashlib.sha384(content).hexdigest()!=expected:
            raise ContractError('CHUNK_MISMATCH')
        key=(tenant,chunk_id)
        if key in self.staged and self.staged[key]!=content:
            raise ContractError('IDEMPOTENCY_CONFLICT')
        self.staged[key]=content
    def validate(self, tenant: str, import_id: str, chunks: list[str], mapping: str) -> str:
        if not chunks or len(chunks)>2048 or len(chunks)!=len(set(chunks)):
            raise ContractError('CHUNK_LIMIT')
        hashes=[]
        for c in chunks:
            if (tenant,c) not in self.staged:
                raise ContractError('CHUNK_NOT_OWNED')
            hashes.append(hashlib.sha384(self.staged[(tenant,c)]).hexdigest())
        digest=hashlib.sha384(canonical_json({'mapping':mapping,'chunks':hashes})).hexdigest()
        key=(tenant,import_id); value=(digest,tuple(chunks))
        if key in self.validated and self.validated[key]!=value:
            raise ContractError('IDEMPOTENCY_CONFLICT')
        self.validated[key]=value
        return digest
    def commit(self, tenant: str, import_id: str, expected: str) -> str:
        key=(tenant,import_id)
        if key not in self.validated or self.validated[key][0]!=expected:
            raise ContractError('IMPORT_NOT_VALIDATED')
        if key in self.published and self.published[key]!=expected:
            raise ContractError('IDEMPOTENCY_CONFLICT')
        self.published[key]=expected
        return expected

def translate_to_draft(*, expected_entity: str, instruction: Mapping[str,Any],
                       now: int, permitted: bool) -> dict[str,Any]:
    if instruction['scope']['legal_entity_id']!=expected_entity:
        raise ContractError('ENTITY_SCOPE_DENIED')
    if not permitted or uint(instruction['expires_at'])<=now:
        raise ContractError('POLICY_DENIED')
    if instruction['requested_action'] not in {
        'DRAFT_RESERVE_ALLOCATION','DRAFT_RESEARCH_COMMITMENT',
        'DRAFT_CAPABILITY_ACQUISITION','DRAFT_PRODUCT_REFERRAL'}:
        raise ContractError('DRAFT_ONLY')
    digest=body_id('PortfolioInstructionV1_2',instruction)
    return {'draft_id':'draft-'+digest[:24], 'effect':'PLAN',
            'financial_authorized':False,'local_authorized':False,
            'source_body_id':digest}

def growth_bridge(*, external_in: int, external_out: int, internal_in: int,
                  internal_out: int, performance: int) -> dict[str,int]:
    return {'new_firm_assets':external_in-external_out,
            'product_change':external_in-external_out+internal_in-internal_out+performance}
