"""Chain-qualified asset identities. A symbol is never an asset identifier."""
from dataclasses import dataclass
import re
from .canonical import hex32, integer
from .errors import require

@dataclass(frozen=True)
class Asset:
    family: str
    genesis: str
    chain_id: int = 0
    token: str = "native"

    def __post_init__(self):
        require(self.family in {"btx", "btc", "evm"}, "ASSET_FAMILY", "Unsupported chain family")
        hex32(self.genesis)
        integer(self.chain_id, lo=0)
        if self.family == "evm":
            require(self.chain_id > 0, "CHAIN_ID", "EVM chain ID required")
            require(self.token == "native" or re.fullmatch(r"0x[0-9a-f]{40}", self.token), "TOKEN", "Invalid ERC-20 address")
        else:
            require(self.chain_id == 0 and self.token == "native", "ASSET_KIND", "Only native BTC/BTX supported")

    @property
    def id(self):
        return f"{self.family}:{self.genesis}:{self.chain_id}:{self.token}"

    @classmethod
    def parse(cls, value):
        require(type(value) is str and len(value) <= 160, "ASSET_ID", "Invalid asset identifier")
        parts = value.split(":")
        require(len(parts) == 4 and parts[2].isdigit() and str(int(parts[2])) == parts[2], "ASSET_ID", "Noncanonical asset identifier")
        return cls(parts[0], parts[1], int(parts[2]), parts[3])

BTC_MAIN_GENESIS = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
BTC_REGTEST_GENESIS = "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
# The BTX genesis is obtained from the trusted local btxd, not guessed from a ticker.
