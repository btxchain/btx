"""Frozen two-chain settlement agreement, separate from an indicative price quote."""
from dataclasses import asdict,dataclass
from .canonical import exact_fields,atoms,hex32,digest,integer
from .assets import Asset
from .policy import Deadline
from .errors import require

@dataclass(frozen=True)
class LegTerms:
    asset:str
    amount_atoms:str
    hashlock:str
    claim_key:str
    refund_key:str
    payout:str
    refund_payout:str
    lock_domain:str
    lock_value:int
    lock_commitment:str
    max_claim_fee_atoms:str
    max_refund_fee_atoms:str
    def __post_init__(self):
        a=Asset.parse(self.asset);atoms(self.amount_atoms,positive=True);hex32(self.hashlock)
        for s in (self.claim_key,self.refund_key,self.payout,self.refund_payout,self.lock_commitment):
            require(type(s) is str and 0<len(s)<=16384,'LEG_FIELD','Invalid leg field')
        require(self.claim_key!=self.refund_key,'KEY_REUSE','Distinct claim/refund authorities required')
        Deadline(self.lock_domain,self.lock_value)
        require(self.lock_domain==('timestamp' if a.family=='evm' else 'height'),'LOCK_DOMAIN','Wrong chain deadline domain')
        require(atoms(self.max_claim_fee_atoms)<atoms(self.amount_atoms),'FEE','Claim fee consumes lock')
        atoms(self.max_refund_fee_atoms)
    @classmethod
    def parse(cls,d):exact_fields(d,cls.__dataclass_fields__);return cls(**d)

@dataclass(frozen=True)
class Agreement:
    network:str
    quote_id:str
    initiator:str
    responder:str
    nonce:str
    long_leg:LegTerms
    short_leg:LegTerms
    def __post_init__(self):
        for s in (self.network,self.quote_id,self.nonce):hex32(s)
        require(self.initiator!=self.responder,'SELF_SWAP','Parties must differ')
        require(self.long_leg.hashlock==self.short_leg.hashlock,'HASHLOCK','Legs must use identical SHA256 bytes')
        require(self.long_leg.asset!=self.short_leg.asset,'PAIR','Leg assets must differ')
        require('btx' in (Asset.parse(self.long_leg.asset).family,Asset.parse(self.short_leg.asset).family),
                'PAIR','This profile requires a native BTX leg')
    @property
    def id(self):return digest('BTX/SWAPNET/AGREEMENT/1',asdict(self))
    @property
    def signing_message(self):return 'BTX/SWAPNET/AGREEMENT/1:'+self.id
    def verify(self,quote,signatures,verify_identity):
        require(quote.id==self.quote_id and quote.network==self.network and quote.provider==self.responder,
                'AGREEMENT_BINDING','Wrong quote, network, or provider')
        require((self.long_leg.asset,self.short_leg.asset,self.long_leg.amount_atoms)==
                (quote.sell_asset,quote.buy_asset,quote.sell_atoms),'AGREEMENT_BINDING','Incorrect locked assets or amount')
        # Maker fee is deducted BEFORE funding; claimant mining fee is paid from
        # the short lock, except EVM where the separate gas budget is disclosed.
        require(atoms(self.short_leg.amount_atoms)==atoms(quote.buy_atoms)-atoms(quote.maker_fee_atoms),
                'AGREEMENT_BINDING','Incorrect maker payout')
        require(atoms(self.short_leg.max_claim_fee_atoms)<=atoms(quote.max_receive_network_fee_atoms),
                'AGREEMENT_BINDING','Claim fee exceeds quote')
        exact_fields(signatures,{'initiator','responder'})
        for role in ('initiator','responder'):
            require(verify_identity(getattr(self,role),signatures[role],self.signing_message) is True,
                    'BAD_SIGNATURE','Agreement signature failed')
        return True
    @classmethod
    def parse(cls,d):
        exact_fields(d,cls.__dataclass_fields__)
        return cls(**{**d,'long_leg':LegTerms.parse(d['long_leg']),'short_leg':LegTerms.parse(d['short_leg'])})
