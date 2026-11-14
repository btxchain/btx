"""Signed executable quote format and deterministic, oracle-free ranking."""
from dataclasses import dataclass, asdict
from .assets import Asset
from .canonical import atoms, digest, exact_fields, hex32, integer
from .errors import require

@dataclass(frozen=True)
class Quote:
    network: str
    provider: str
    requester: str
    nonce: str
    sequence: int
    sell_asset: str
    buy_asset: str
    sell_atoms: str
    buy_atoms: str
    maker_fee_atoms: str
    max_receive_network_fee_atoms: str
    issued_at: int
    expires_at: int
    settlement: str = "sha256-htlc-v1"

    def __post_init__(self):
        hex32(self.network); hex32(self.nonce); hex32(self.requester)
        require(type(self.provider) is str and 1 <= len(self.provider) <= 256, "PROVIDER", "Invalid provider identity")
        Asset.parse(self.sell_asset); Asset.parse(self.buy_asset)
        require(self.sell_asset != self.buy_asset, "PAIR", "Identical assets cannot be swapped")
        atoms(self.sell_atoms, positive=True)
        require(atoms(self.buy_atoms, positive=True) > atoms(self.maker_fee_atoms) + atoms(self.max_receive_network_fee_atoms), "NET_AMOUNT", "Fees consume received amount")
        integer(self.sequence, lo=1); integer(self.issued_at); integer(self.expires_at, lo=self.issued_at+1)
        require(self.expires_at-self.issued_at <= 120, "QUOTE_TTL", "Quote lifetime exceeds 120 seconds")
        require(self.settlement == "sha256-htlc-v1", "SETTLEMENT", "Unknown settlement protocol")

    @classmethod
    def parse(cls, obj):
        exact_fields(obj, cls.__dataclass_fields__)
        return cls(**obj)

    @property
    def id(self): return digest("BTX/SWAPNET/QUOTE/1", asdict(self))
    @property
    def net_buy(self): return atoms(self.buy_atoms)-atoms(self.maker_fee_atoms)-atoms(self.max_receive_network_fee_atoms)
    @property
    def signing_message(self): return "BTX/SWAPNET/QUOTE/1:" + self.id
    def live(self, now): return self.issued_at <= now < self.expires_at

class SignedQuote:
    def __init__(self, quote, signature):
        self.quote = quote
        require(type(signature) is str and 1 <= len(signature) <= 16384, "SIGNATURE", "Invalid signature encoding")
        self.signature = signature
    def verify(self, verify_message, network, requester, now):
        q = self.quote
        require(q.network == network and q.requester == requester, "QUOTE_BINDING", "Wrong network or requester")
        require(q.live(now), "QUOTE_EXPIRED", "Quote not live")
        require(verify_message(q.provider, self.signature, q.signing_message) is True, "BAD_SIGNATURE", "Quote identity signature rejected")
        return q
    def as_dict(self): return {"quote": asdict(self.quote), "signature": self.signature}


def rank_quotes(quotes, sell_asset, buy_asset, sell_atoms, now):
    amount = atoms(sell_atoms, positive=True)
    valid = [q for q in quotes if q.sell_asset == sell_asset and q.buy_asset == buy_asset
             and atoms(q.sell_atoms) == amount and q.live(now)]
    # Exact size only: no misleading averages, fractional fills or hidden multi-route risk.
    return sorted(valid, key=lambda q: (-q.net_buy, q.expires_at, q.id))
