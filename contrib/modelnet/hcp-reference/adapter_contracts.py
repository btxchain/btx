"""Typed integration seams, not implemented exchange adapters."""
from dataclasses import dataclass
from enum import Enum
from typing import Protocol

class Certainty(str,Enum):
    NOT_APPLIED='NOT_APPLIED'
    APPLIED='APPLIED'
    UNKNOWN='UNKNOWN'

@dataclass(frozen=True)
class Caller:
    tenant: str
    account: str
    principal: str
    scopes: frozenset[str]

@dataclass(frozen=True)
class EffectOutcome:
    operation_id: str
    certainty: Certainty
    result_ref: str|None

class LedgerAdapter(Protocol):
    def reserve(self,caller:Caller,intent_digest:str,total_atoms:str,fence:int)->EffectOutcome: ...
    def lookup(self,operation_id:str)->EffectOutcome: ...
    def settle(self,operation_id:str,actual_atoms:str,fence:int)->EffectOutcome: ...

class CustodyAdapter(Protocol):
    def inspect_native_template(self,template:bytes,terms:bytes)->dict: ...
    def sign_exact(self,operation_id:str,approved_digest:str,transaction:bytes,fence:int)->EffectOutcome: ...
    def lookup_signature(self,operation_id:str)->EffectOutcome: ...

class ChainObserver(Protocol):
    def observe(self,transaction_id:str,outpoints:list[str])->dict: ...

class AdapterError(RuntimeError):
    """Stable partner-adapter failure. UNKNOWN is not represented as an error."""
    def __init__(self,code:str,message:str=''):
        super().__init__(code if not message else f'{code}: {message}')
        self.code=code

class NativeFamily(str,Enum):
    BTX_NATIVE_TEMPLATES='BTX_NATIVE_TEMPLATES'
    EVM_GENERIC='EVM_GENERIC'
    DISABLED='DISABLED'

EVIDENCE_SIMULATION_ONLY='SIMULATION_ONLY'
AUTOMATIC_SPEND_ATOMS=0

class DisabledProductionSigner:
    def inspect_native_template(self,template:bytes,terms:bytes)->dict:
        raise RuntimeError('CUSTODY_UNSUPPORTED: supply independently tested native signer')
    def sign_exact(self,*args,**kwargs):
        raise RuntimeError('CUSTODY_UNSUPPORTED: supply independently tested native signer')
    def lookup_signature(self,operation_id:str)->EffectOutcome:
        raise RuntimeError('CUSTODY_UNSUPPORTED: supply independently tested native signer')

class IdentityAdapter(Protocol):
    def verify_caller(self,token_reference:str,audience:str,sender_proof:bytes)->Caller: ...

class EligibilityAdapter(Protocol):
    def decide(self,caller:Caller,action:str,terms_id:str,policy_version:str)->dict: ...

class QuoteAdapter(Protocol):
    def firm_conversion_quote(self,caller:Caller,source_asset:str,max_source_minor:str,target_btx_atoms:str)->dict: ...
    def execute_exact_quote(self,caller:Caller,quote_ref:str,operation_id:str)->EffectOutcome: ...
    def lookup_conversion(self,operation_id:str)->EffectOutcome: ...

class NativeEconomyAdapter(Protocol):
    def inspect_terms(self,network_id:str,terms_id:str)->bytes: ...
    def prepare_exact(self,caller:Caller,action:str,terms_id:str,principal_atoms:str,fee_cap_atoms:str)->dict: ...
    def verify_frozen_transaction(self,transaction:bytes,terms:bytes)->dict: ...

class PackageAdapter(Protocol):
    def read_exact_package(self,package_core_id:str,max_bytes:int)->bytes: ...
    def search_verified(self,query:str,limit:int,cursor:str|None)->dict: ...

class AuditAdapter(Protocol):
    def append_once(self,business_event_id:str,redacted_event:dict)->EffectOutcome: ...

class ReportingAdapter(Protocol):
    def export_customer(self,caller:Caller,operation_id:str,include:list[str])->dict: ...

class WebhookAdapter(Protocol):
    """Optional event-delivery enrollment. Destinations are allowlisted HTTPS only."""
    def enroll(self,destination_url:str,delivery_id:str)->EffectOutcome: ...
