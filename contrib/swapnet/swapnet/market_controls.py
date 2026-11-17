"""Exact, owner-configured execution controls. No oracle or counterparty is trusted by default.

These functions evaluate already signature-verified quotes. They do not verify a
blockchain, claim economic independence of identities, or authorize a wallet.
"""
from dataclasses import asdict, dataclass, field
from fractions import Fraction
import hashlib
import json
import re
from typing import Any, Iterable

MAX_ATOMS = (1 << 256) - 1

from .errors import SwapError

class ControlError(SwapError):
    def __init__(self, code: str, message: str):
        self.code, self.message = code, message
        super().__init__(code, message)

def require(ok: bool, code: str, message: str) -> None:
    if not ok:
        raise ControlError(code, message)

def amount(value: Any, *, positive: bool = False) -> int:
    require(type(value) is str and 0 < len(value) <= 78 and
            re.fullmatch(r"0|[1-9][0-9]*", value) is not None,
            "AMOUNT", "An atomic amount must be a canonical decimal string")
    n = int(value)
    require(n <= MAX_ATOMS and (n > 0 if positive else n >= 0), "AMOUNT", "Amount outside range")
    return n

def integer(value: Any, low: int, high: int, name: str) -> int:
    require(type(value) is int and low <= value <= high, "POLICY", f"Invalid {name}")
    return value

def canonical(value: Any) -> bytes:
    try:
        data = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()
    except (ValueError, TypeError) as exc:
        raise ControlError("POLICY", "Invalid canonical value") from exc
    require(len(data) <= 65536, "LIMIT", "Control value exceeds 64 KiB")
    return data

def fingerprint(value: Any) -> str:
    return hashlib.sha256(b"BTX/SWAPNET/LOCAL-CONTROL/1\x00" + canonical(value)).hexdigest()

@dataclass(frozen=True)
class Reference:
    source: str
    sell_asset: str
    buy_asset: str
    numerator: str
    denominator: str
    observed_at: int
    expires_at: int

    def __post_init__(self):
        require(type(self.source) is str and 0 < len(self.source) <= 128, "REFERENCE", "Invalid owner-selected source")
        require(type(self.sell_asset) is str and type(self.buy_asset) is str and
                self.sell_asset != self.buy_asset, "REFERENCE", "Reference pair required")
        amount(self.numerator, positive=True); amount(self.denominator, positive=True)
        integer(self.observed_at, 0, (1 << 53)-1, "reference time")
        integer(self.expires_at, self.observed_at+1, (1 << 53)-1, "reference expiry")

    @property
    def rate(self) -> Fraction:
        return Fraction(amount(self.numerator), amount(self.denominator))

@dataclass(frozen=True)
class ExecutionPolicy:
    min_provider_identities: int = 1
    max_reference_deviation_bps: int | None = None
    max_reference_age_seconds: int = 300
    reference_quorum: int = 1
    max_receive_fee_bps: int = 10000
    minimum_receive_atoms: str = "0"
    excluded_providers: tuple[str, ...] = field(default_factory=tuple)
    references: tuple[Reference, ...] = field(default_factory=tuple)

    def __post_init__(self):
        integer(self.min_provider_identities, 1, 128, "provider identity count")
        if self.max_reference_deviation_bps is not None:
            integer(self.max_reference_deviation_bps, 0, 10000, "deviation")
        integer(self.max_reference_age_seconds, 1, 86400, "reference age")
        integer(self.reference_quorum, 1, 16, "reference quorum")
        integer(self.max_receive_fee_bps, 0, 10000, "fee fraction")
        amount(self.minimum_receive_atoms)
        require(len(self.excluded_providers) <= 128 and all(type(x) is str and 0 < len(x) <= 256 for x in self.excluded_providers),
                "POLICY", "Invalid excluded providers")
        require(len(self.references) <= 16 and len({r.source for r in self.references}) == len(self.references),
                "REFERENCE", "References must have distinct configured source names")

    @classmethod
    def parse(cls, obj: dict) -> 'ExecutionPolicy':
        require(type(obj) is dict and not (set(obj)-set(cls.__dataclass_fields__)), "POLICY", "Unknown policy fields")
        body = dict(obj)
        body['excluded_providers'] = tuple(body.get('excluded_providers', ()))
        body['references'] = tuple(Reference(**r) for r in body.get('references', ()))
        return cls(**body)

    def document(self) -> dict:
        return asdict(self)

    @property
    def digest(self) -> str:
        return fingerprint(self.document())


def reference_rate(policy: ExecutionPolicy, sell: str, buy: str, now: int) -> Fraction | None:
    values = [r.rate for r in policy.references if r.sell_asset == sell and r.buy_asset == buy
              and r.observed_at <= now < r.expires_at and now-r.observed_at <= policy.max_reference_age_seconds]
    if len(values) < policy.reference_quorum:
        return None
    values.sort()
    # Exact median, including even-sized source sets; no float conversion.
    i = len(values)//2
    return values[i] if len(values)%2 else (values[i-1]+values[i])/2


def evaluate_quote(quote: dict, candidates: Iterable[dict], policy: ExecutionPolicy, now: int) -> dict:
    """Returns reasons rather than manufacturing a quote or changing its price."""
    sell = amount(quote['sell_atoms'], positive=True)
    gross = amount(quote['buy_atoms'], positive=True)
    maker = amount(quote['maker_fee_atoms'])
    network = amount(quote['max_receive_network_fee_atoms'])
    net = gross-maker-network
    reasons: list[str] = []
    if not quote['issued_at'] <= now < quote['expires_at']: reasons.append('QUOTE_EXPIRED')
    if net <= 0: reasons.append('NET_AMOUNT')
    if quote['provider'] in policy.excluded_providers: reasons.append('PROVIDER_EXCLUDED')
    if net < amount(policy.minimum_receive_atoms): reasons.append('MINIMUM_RECEIVE')
    if (maker+network)*10000 > gross*policy.max_receive_fee_bps: reasons.append('RECEIVE_FEE_LIMIT')
    live = [q for q in candidates if (q['sell_asset'],q['buy_asset'],q['sell_atoms']) ==
            (quote['sell_asset'],quote['buy_asset'],quote['sell_atoms']) and
            q['issued_at'] <= now < q['expires_at'] and q['provider'] not in policy.excluded_providers]
    identities = len({q['provider'] for q in live})
    if identities < policy.min_provider_identities: reasons.append('QUOTE_COVERAGE')
    ref = reference_rate(policy, quote['sell_asset'], quote['buy_asset'], now)
    if policy.max_reference_deviation_bps is not None:
        if ref is None:
            reasons.append('REFERENCE_UNAVAILABLE')
        elif net*ref.denominator*10000 < sell*ref.numerator*(10000-policy.max_reference_deviation_bps):
            reasons.append('PRICE_DEVIATION')
    return {'allowed': not reasons, 'reasons': reasons, 'minimum_receive_atoms': str(max(0,net)),
            'provider_identities': identities, 'identities_are_independent_owners': False,
            'reference': None if ref is None else {'numerator':str(ref.numerator),'denominator':str(ref.denominator)},
            'policy_digest': policy.digest, 'local_view_only': True}

@dataclass(frozen=True)
class MakerPolicy:
    """Optional local limits and inventory skew; these never mint or pool inventory."""
    min_input_atoms: str = "1"
    inventory_floor_atoms: str = "0"
    target_inventory_atoms: str = "0"
    max_inventory_skew_bps: int = 0
    spread_bps: int = 0
    max_quotes_per_requester: int = 8

    def __post_init__(self):
        amount(self.min_input_atoms, positive=True); amount(self.inventory_floor_atoms)
        amount(self.target_inventory_atoms)
        integer(self.max_inventory_skew_bps, 0, 2000, 'inventory skew')
        integer(self.spread_bps, 0, 5000, 'maker spread')
        integer(self.max_quotes_per_requester, 1, 256, 'requester quote limit')

    def quote_terms(self, market: dict, inventory_atoms: str) -> dict:
        inventory = amount(inventory_atoms)
        floor = amount(self.inventory_floor_atoms)
        require(inventory > floor, 'INVENTORY_FLOOR', 'No inventory above owner floor')
        result = dict(market)
        target = amount(self.target_inventory_atoms)
        skew = 0
        if target:
            # More of the outgoing asset -> pay more per unit received to rebalance.
            delta = max(-target, min(target, inventory-target))
            sign = -1 if delta < 0 else 1
            skew = sign*(abs(delta)*self.max_inventory_skew_bps//target)
        factor = 10000-self.spread_bps+skew
        require(factor > 0, 'MARKET_PRICE', 'Price factor is non-positive')
        rate = Fraction(amount(market['numerator'],positive=True)*factor,
                        amount(market['denominator'],positive=True)*10000)
        require(rate.numerator <= MAX_ATOMS and rate.denominator <= MAX_ATOMS, 'MARKET_PRICE', 'Rate exceeds range')
        result.update(numerator=str(rate.numerator), denominator=str(rate.denominator))
        return result

    def effective_minimum(self, market: dict) -> str:
        n = amount(market['numerator'],positive=True); d = amount(market['denominator'],positive=True)
        fees = amount(market['maker_fee_atoms'])+amount(market['max_receive_network_fee_atoms'])
        # floor(x*n/d) >= fees+1
        minimum = ((fees+1)*d+n-1)//n
        return str(max(amount(self.min_input_atoms),minimum))
