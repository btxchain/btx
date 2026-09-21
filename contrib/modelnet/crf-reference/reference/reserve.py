# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Offline conformance reference. Not an exchange ledger, signer or OAuth server."""
from __future__ import annotations
import hashlib, json, re, sqlite3, struct
from decimal import Decimal, InvalidOperation, ROUND_CEILING
from functools import lru_cache
from pathlib import Path
from typing import Any

MAX_ATOMS = (1 << 63) - 1
OBJECT_TYPES_V1_1 = frozenset({
    'ReserveExtensionProfileV1_1', 'EntityLinkV1_1', 'PortfolioV1_1', 'ReservePolicyV1_1',
    'ReserveSnapshotV1_1', 'WorkloadProfileV1_1', 'TCOComparisonV1_1', 'CapitalPlanV1_1',
    'AllocationPlanV1_1', 'ApprovalRuleV1_1', 'ApprovalRequestV1_1', 'ApprovalDecisionV1_1',
    'CapabilityPositionV1_1', 'ResearchProgramV1_1', 'ProgramMembershipV1_1', 'ProductOfferV1_1',
    'CapitalExecutionReceiptV1_1', 'ReserveReportV1_1',
})


class ContractError(ValueError):
    pass


def atoms(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0 or value > MAX_ATOMS:
        raise ContractError('INVALID_ATOMS')
    return value


def uint_string(value: str) -> int:
    if not isinstance(value, str) or not re.fullmatch(r'0|[1-9][0-9]{0,19}', value):
        raise ContractError('INVALID_UINT_STRING')
    return atoms(int(value))


def capacity(available: int, protected: int, remaining_authority: int) -> int:
    return max(0, min(atoms(available) - atoms(protected), atoms(remaining_authority)))


def decimal(value: Any) -> Decimal:
    if isinstance(value, (float, bool)):
        raise ContractError('USE_EXACT_DECIMAL')
    try:
        d = Decimal(value)
    except (InvalidOperation, ValueError, TypeError):
        raise ContractError('INVALID_DECIMAL')
    if not d.is_finite() or d < 0:
        raise ContractError('INVALID_DECIMAL')
    return d


def reporting_floor_atoms(required_quote: str, price_quote_per_coin: str, exponent: int,
                          observed_at: int, now: int, max_age: int, haircut_bps: int = 0) -> int:
    need = decimal(required_quote)
    price = decimal(price_quote_per_coin)
    if not 0 <= exponent <= 18 or not 0 <= haircut_bps < 10000:
        raise ContractError('INVALID_PRICE_POLICY')
    if observed_at > now or now - observed_at > max_age:
        raise ContractError('PRICE_STALE')
    price = price * (Decimal(10000 - haircut_bps) / Decimal(10000))
    if price <= 0:
        raise ContractError('INVALID_PRICE')
    return atoms(int((need / price * (Decimal(10) ** exponent)).to_integral_value(rounding=ROUND_CEILING)))


def tco(annual_tasks: str, service_per_task: str, years: int, upfront: str, annual_local: str,
        *, quality_equivalent: bool = True, inputs_known: bool = True) -> dict[str, Decimal | None]:
    if not quality_equivalent:
        raise ContractError('QUALITY_UNPROVEN')
    if not inputs_known:
        raise ContractError('INPUT_UNKNOWN')
    if isinstance(years, bool) or not isinstance(years, int) or not 1 <= years <= 10:
        raise ContractError('INVALID_HORIZON')
    tasks, unit, fixed, annual = map(decimal, (annual_tasks, service_per_task, upfront, annual_local))
    external = tasks * unit * years
    local = fixed + annual * years
    return {'external': external, 'local': local, 'difference': external - local,
            'break_even_annual_tasks': local / (unit * years) if unit else None}


def canonical_bytes(value: Any) -> bytes:
    nodes = 0

    def check(v, depth=0):
        nonlocal nodes
        nodes += 1
        if nodes > 65536 or depth > 32:
            raise ContractError('JSON_LIMIT')
        if v is None or isinstance(v, bool):
            return
        if isinstance(v, int):
            if abs(v) > 2 ** 53 - 1:
                raise ContractError('UNSAFE_JSON_INTEGER')
        elif isinstance(v, float):
            raise ContractError('FLOAT_FORBIDDEN')
        elif isinstance(v, str):
            try:
                v.encode('utf8')
            except UnicodeEncodeError:
                raise ContractError('INVALID_UNICODE')
        elif isinstance(v, list):
            for x in v:
                check(x, depth + 1)
        elif isinstance(v, dict):
            for k, x in v.items():
                if not isinstance(k, str) or not k.isascii():
                    raise ContractError('NON_ASCII_KEY')
                check(k, depth + 1)
                check(x, depth + 1)
        else:
            raise ContractError('UNSUPPORTED_JSON_TYPE')

    check(value)
    b = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode('utf8')
    if len(b) > 1048576:
        raise ContractError('BODY_TOO_LARGE')
    return b


def parse_canonical(raw: bytes) -> Any:
    if len(raw) > 1048576:
        raise ContractError('BODY_TOO_LARGE')

    def pairs(ps):
        d = {}
        for k, v in ps:
            if k in d:
                raise ContractError('DUPLICATE_KEY')
            d[k] = v
        return d

    def pi(s):
        if s == '-0':
            raise ContractError('NEGATIVE_ZERO')
        return int(s)

    def bad(s):
        raise ContractError('FLOAT_FORBIDDEN')

    try:
        v = json.loads(raw.decode('utf8'), object_pairs_hook=pairs, parse_int=pi, parse_float=bad, parse_constant=bad)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ContractError('INVALID_JSON')
    if canonical_bytes(v) != raw:
        raise ContractError('NON_CANONICAL')
    return v


def _schema_candidates() -> list[Path]:
    out: list[Path] = []
    here = Path(__file__).resolve()
    for parent in [here.parent, *here.parents]:
        out.append(parent / 'schemas' / 'CognitiveReserve.schema.json')
        out.append(parent / 'src' / 'modelnet' / 'crf' / 'schemas' / 'CognitiveReserve.schema.json')
    return out


@lru_cache(maxsize=1)
def _object_types() -> frozenset[str]:
    for cand in _schema_candidates():
        if cand.is_file():
            schema = json.loads(cand.read_text())
            return frozenset(n for n in schema.get('$defs', {}) if n.endswith('V1_1'))
    return OBJECT_TYPES_V1_1


def body_id(kind: str, body: dict) -> str:
    if kind not in _object_types():
        raise ContractError('UNSUPPORTED_OBJECT_TYPE')
    data = canonical_bytes(body)
    return hashlib.sha384(('BTX/HCP/' + kind + '/v1').encode() + b'\0' + struct.pack('<Q', len(data)) + data).hexdigest()


def validate_dag(legs: list[dict]) -> list[str]:
    if not legs or len(legs) > 32:
        raise ContractError('GRAPH_LIMIT')
    by = {x['leg_id']: x for x in legs}
    if len(by) != len(legs):
        raise ContractError('DUPLICATE_LEG')
    out: list[str] = []
    active: set[str] = set()
    done: set[str] = set()
    depth_of: dict[str, int] = {}

    def visit(k: str) -> int:
        if k not in by:
            raise ContractError('MISSING_DEPENDENCY')
        if k in active:
            raise ContractError('GRAPH_CYCLE')
        if k in done:
            return depth_of[k]
        active.add(k)
        depth = 1
        for dep in by[k].get('depends_on', []):
            depth = max(depth, 1 + visit(dep))
        active.remove(k)
        done.add(k)
        depth_of[k] = depth
        out.append(k)
        if depth > 16:
            raise ContractError('GRAPH_DEPTH')
        return depth

    for k in by:
        visit(k)
    return out


def approved(decisions: list[dict], *, entity: str, plan: str, policy_generation: str, rule: str,
             eligible_people: set[str], quorum: int, initiator: str, now: int,
             exclude_initiator: bool = True, veto: bool = True) -> bool:
    if not 1 <= quorum <= 32:
        raise ContractError('INVALID_QUORUM')
    latest: dict[str, dict] = {}
    for d in decisions:
        if d['entity'] != entity or d['plan'] != plan or d['policy_generation'] != policy_generation or d['rule'] != rule:
            continue
        p = d['person']
        seq = d['sequence']
        if p not in eligible_people or d['expires_at'] < now or (exclude_initiator and p == initiator):
            continue
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
            raise ContractError('INVALID_SEQUENCE')
        if p in latest and latest[p]['sequence'] == seq and latest[p] != d:
            raise ContractError('DECISION_EQUIVOCATION')
        if p not in latest or seq > latest[p]['sequence']:
            latest[p] = d
    if veto and any(d['decision'] == 'REJECT' for d in latest.values()):
        return False
    return sum(d['decision'] == 'APPROVE' for d in latest.values()) >= quorum


class AtomicLedger:
    """SQLite reference of reservation/uncertainty invariants; synthetic amounts only."""

    def __init__(self, path: str):
        self.path = path
        with self.connect() as c:
            c.executescript('''PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS accounts(entity TEXT PRIMARY KEY,available INTEGER NOT NULL,protected INTEGER NOT NULL,authority INTEGER NOT NULL,spent INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS operations(entity TEXT NOT NULL,id TEXT NOT NULL,digest TEXT NOT NULL,amount INTEGER NOT NULL,state TEXT NOT NULL,PRIMARY KEY(entity,id));
            CREATE TABLE IF NOT EXISTS journal(seq INTEGER PRIMARY KEY AUTOINCREMENT,entity TEXT NOT NULL,operation TEXT NOT NULL,state TEXT NOT NULL,amount INTEGER NOT NULL);''')

    def connect(self):
        return sqlite3.connect(self.path, timeout=30, isolation_level=None)

    def account(self, entity: str, available: int, protected: int, authority: int):
        with self.connect() as c:
            c.execute('INSERT INTO accounts(entity,available,protected,authority) VALUES(?,?,?,?)',
                      (entity, atoms(available), atoms(protected), atoms(authority)))

    def reserve(self, entity: str, op: str, digest: str, amount: int) -> str:
        atoms(amount)
        if amount == 0:
            raise ContractError('ZERO_RESERVATION')
        c = self.connect()
        try:
            c.execute('BEGIN IMMEDIATE')
            prior = c.execute('SELECT digest,amount,state FROM operations WHERE entity=? AND id=?', (entity, op)).fetchone()
            if prior:
                if prior[0] != digest or prior[1] != amount:
                    raise ContractError('IDEMPOTENCY_CONFLICT')
                c.commit()
                return prior[2]
            a = c.execute('SELECT available,protected,authority,spent FROM accounts WHERE entity=?', (entity,)).fetchone()
            if not a:
                raise ContractError('ENTITY_SCOPE_DENIED')
            held = c.execute("SELECT COALESCE(SUM(amount),0) FROM operations WHERE entity=? AND state IN ('HELD','SIGNED','UNKNOWN')",
                             (entity,)).fetchone()[0]
            if amount > capacity(a[0], a[1], max(0, a[2] - a[3] - held)):
                raise ContractError('CAPACITY_EXCEEDED')
            c.execute('UPDATE accounts SET available=available-? WHERE entity=?', (amount, entity))
            c.execute('INSERT INTO operations VALUES(?,?,?,?,?)', (entity, op, digest, amount, 'HELD'))
            c.execute('INSERT INTO journal(entity,operation,state,amount) VALUES(?,?,?,?)', (entity, op, 'HELD', amount))
            c.commit()
            return 'HELD'
        except Exception:
            c.rollback()
            raise
        finally:
            c.close()

    def transition(self, entity: str, op: str, target: str) -> str:
        c = self.connect()
        try:
            c.execute('BEGIN IMMEDIATE')
            row = c.execute('SELECT amount,state FROM operations WHERE entity=? AND id=?', (entity, op)).fetchone()
            if not row:
                raise ContractError('OPERATION_NOT_FOUND')
            amount, state = row
            if state == target:
                c.commit()
                return state
            allowed = {'HELD': {'SIGNED', 'UNKNOWN', 'SETTLED', 'CANCELED'}, 'SIGNED': {'UNKNOWN', 'SETTLED'},
                       'UNKNOWN': {'SETTLED'}, 'SETTLED': {'REFUNDED'}, 'CANCELED': set(), 'REFUNDED': set()}
            if target not in allowed[state]:
                raise ContractError('UNSAFE_TRANSITION')
            if target in {'CANCELED', 'REFUNDED'}:
                c.execute('UPDATE accounts SET available=available+? WHERE entity=?', (amount, entity))
            if target == 'SETTLED':
                c.execute('UPDATE accounts SET spent=spent+? WHERE entity=?', (amount, entity))
            c.execute('UPDATE operations SET state=? WHERE entity=? AND id=?', (target, entity, op))
            c.execute('INSERT INTO journal(entity,operation,state,amount) VALUES(?,?,?,?)', (entity, op, target, amount))
            c.commit()
            return target
        except Exception:
            c.rollback()
            raise
        finally:
            c.close()

    def snapshot(self, entity: str) -> dict:
        c = self.connect()
        try:
            c.execute('BEGIN')
            a = c.execute('SELECT available,protected,authority,spent FROM accounts WHERE entity=?', (entity,)).fetchone()
            if not a:
                raise ContractError('ENTITY_SCOPE_DENIED')
            held = c.execute("SELECT COALESCE(SUM(amount),0) FROM operations WHERE entity=? AND state IN ('HELD','SIGNED','UNKNOWN')",
                             (entity,)).fetchone()[0]
            rem = max(0, a[2] - a[3] - held)
            c.commit()
            return dict(available=a[0], protected=a[1], authority=a[2], spent=a[3], held=held,
                        remaining_authority=rem, capacity=capacity(a[0], a[1], rem))
        finally:
            c.close()
