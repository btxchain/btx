"""Conservative timing and budget policy; estimated block time is not a guarantee."""
from dataclasses import dataclass, asdict
from .canonical import integer, atoms, digest, hex32
from .assets import Asset
from .errors import require

@dataclass(frozen=True)
class ChainClock:
    family: str
    height: int
    timestamp: int
    observed_at: int
    fastest_block_seconds: int
    slowest_block_seconds: int
    stalled: bool = False

    def __post_init__(self):
        require(self.family in {"btx", "btc", "evm"}, "CHAIN_CLOCK", "Unknown chain")
        for v in (self.height, self.timestamp, self.observed_at): integer(v)
        integer(self.fastest_block_seconds, lo=1)
        integer(self.slowest_block_seconds, lo=self.fastest_block_seconds)
        require(type(self.stalled) is bool, "CHAIN_CLOCK", "stalled must be boolean")

@dataclass(frozen=True)
class Deadline:
    domain: str
    value: int

    def __post_init__(self):
        require(self.domain in {"height", "timestamp"}, "LOCK_DOMAIN", "Unknown deadline domain")
        integer(self.value, lo=1)
        if self.domain == "height": require(self.value < 500_000_000, "LOCK_DOMAIN", "Height enters CLTV timestamp domain")
        else: require(self.value >= 500_000_000, "LOCK_DOMAIN", "Timestamp is implausible")

    def remaining(self, clock: ChainClock):
        if self.domain == "timestamp":
            seconds = max(0, self.value - clock.timestamp)
            return seconds, seconds
        blocks = max(0, self.value - clock.height)
        return blocks * clock.fastest_block_seconds, blocks * clock.slowest_block_seconds

@dataclass(frozen=True)
class SafetyPolicy:
    btx_confirmations: int = 20
    btc_confirmations: int = 6
    settlement_margin_seconds: int = 7200
    reveal_margin_seconds: int = 3600
    max_observation_age_seconds: int = 60
    quote_ttl_seconds: int = 120
    require_evm_finalized: bool = True

    def __post_init__(self):
        for name in ("btx_confirmations", "btc_confirmations", "settlement_margin_seconds", "reveal_margin_seconds", "max_observation_age_seconds", "quote_ttl_seconds"):
            integer(getattr(self, name), lo=1)
        require(type(self.require_evm_finalized) is bool, "POLICY", "Invalid finality policy")

    def confirmations(self, family):
        if family == "btx": return self.btx_confirmations
        if family == "btc": return self.btc_confirmations
        return 1

    def check_clocks(self, now, *clocks):
        integer(now)
        for c in clocks:
            require(not c.stalled and 0 <= now-c.observed_at <= self.max_observation_age_seconds,
                    "STALE_CHAIN", "Chain observation is stale or stalled")

    def validate_deadlines(self, long, short, clock_a, clock_b, now):
        self.check_clocks(now, clock_a, clock_b)
        a_min, _ = long.remaining(clock_a)
        _, b_max = short.remaining(clock_b)
        require(a_min >= b_max + self.settlement_margin_seconds, "UNSAFE_TIMEOUT", "Long leg does not conservatively outlive short leg")
        require(short.remaining(clock_b)[0] > self.reveal_margin_seconds, "LATE_REVEAL", "Short leg is too close to expiry")
        return True

@dataclass(frozen=True)
class Mandate:
    principal: str
    asset: str
    max_total_atoms: str
    max_trade_atoms: str
    max_fee_atoms: str
    expires_at: int
    nonce: str

    def __post_init__(self):
        Asset.parse(self.asset)
        require(type(self.principal) is str and 1 <= len(self.principal) <= 128, "PRINCIPAL", "Invalid principal")
        require(atoms(self.max_trade_atoms, positive=True) <= atoms(self.max_total_atoms, positive=True), "MANDATE", "Per-trade cap exceeds total")
        atoms(self.max_fee_atoms)
        integer(self.expires_at, lo=1)
        hex32(self.nonce)

    @property
    def id(self): return digest("BTX/SWAPNET/MANDATE/1", asdict(self))
