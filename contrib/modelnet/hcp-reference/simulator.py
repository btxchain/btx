"""No-I/O, no-money simulator for selected HCP intent invariants.

A process-local lock is deliberately NOT production multi-replica persistence.
Nothing here signs, broadcasts, verifies a chain or executes a runtime.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from copy import deepcopy
from threading import RLock
from typing import Any
from .contracts import ContractError, atoms, body_id, validate_amounts

@dataclass
class Intent:
    body: dict[str, Any]
    digest: str
    state: str='PREPARED'
    sim_tx_ref: str|None=None
    dispatch_attempts: int=0
    charged: int=0
    refunded: bool=False

class Simulation:
    evidence='SIMULATION_ONLY'
    def __init__(self,balance: int,policy: dict[str,Any]):
        if balance<0:raise ValueError('negative balance')
        self.balance=balance;self.policy=deepcopy(policy);self.intents={};self.holds={}
        self.consumed_principal=0;self.consumed_fees=0;self.exposure=0;self.action_count=0
        self.lock=RLock()
    @property
    def available(self)->int:
        return self.balance-sum(self.holds.values())
    def create(self,body:dict[str,Any])->Intent:
        with self.lock:
            b=deepcopy(body);validate_amounts(b['amounts'])
            key=(b['provider_id'],b['account_ref'],b['client_operation_id']);digest=body_id('FinanceIntent',b)
            if key in self.intents:
                previous=self.intents[key]
                if previous.digest!=digest:raise ContractError('IDEMPOTENCY_CONFLICT')
                return previous
            i=Intent(b,digest);self.intents[key]=i;return i
    def _policy(self,i:Intent,now:int)->None:
        p=self.policy;b=i.body
        if body_id('FinanceIntent',b)!=i.digest:raise ContractError('INTENT_MUTATED')
        if p['revoked'] or atoms(p['expires_at_ms'])<=now:raise ContractError('POLICY_DENIED')
        if b['policy_id']!=p['policy_id'] or b['policy_revision']!=p['revision']:raise ContractError('POLICY_REVISION')
        if b['action'] not in p['allowed_actions']:raise ContractError('ACTION_DENIED')
        # Reference harness implements exact-terms policies only, not future publisher native verification.
        if b['terms_id'] not in p['allowed_terms_ids']:raise ContractError('TERMS_DENIED')
        if atoms(b['expires_at_ms'])<=now:raise ContractError('QUOTE_EXPIRED')
    def authorize(self,i:Intent,expected:str,now:int)->None:
        with self.lock:
            if i.digest!=expected:raise ContractError('INTENT_MISMATCH')
            self._policy(i,now)
            if i.state=='AUTHORIZED':return
            if i.state!='PREPARED':raise ContractError('STATE_CONFLICT')
            i.state='AUTHORIZED'
    def reserve(self,i:Intent,now:int)->None:
        with self.lock:
            self._policy(i,now)
            if i.digest in self.holds:return
            if i.state!='AUTHORIZED':raise ContractError('STATE_CONFLICT')
            a=i.body['amounts'];p=atoms(a['principal_atoms']);fees=validate_amounts(a)-p
            policy=self.policy
            pending=[x for x in self.intents.values() if x.digest in self.holds]
            rp=sum(atoms(x.body['amounts']['principal_atoms']) for x in pending)
            rf=sum(self.holds[x.digest]-atoms(x.body['amounts']['principal_atoms']) for x in pending)
            if p>atoms(policy['per_action_principal_atoms']):raise ContractError('PER_ACTION_LIMIT')
            if self.consumed_principal+rp+p>atoms(policy['lifetime_principal_atoms']):raise ContractError('LIFETIME_LIMIT')
            if self.consumed_fees+rf+fees>atoms(policy['lifetime_fee_atoms']):raise ContractError('FEE_LIMIT')
            if self.exposure+sum(self.holds.values())+p+fees>atoms(policy['outstanding_exposure_atoms']):raise ContractError('EXPOSURE_LIMIT')
            if len(self.holds)>=policy['max_concurrent']:raise ContractError('CONCURRENCY_LIMIT')
            if self.action_count>=policy['max_actions']:raise ContractError('ACTION_COUNT_LIMIT')
            if p+fees>self.available:raise ContractError('INSUFFICIENT_AVAILABLE_BALANCE')
            self.holds[i.digest]=p+fees;self.action_count+=1;i.state='RESERVED'
    def simulate_sign(self,i:Intent,now_ms:int=1790000000100)->str:
        with self.lock:
            self._policy(i,now_ms)
            if i.state not in ['RESERVED','SIGNED']:raise ContractError('STATE_CONFLICT')
            if i.sim_tx_ref is None:i.sim_tx_ref='SIMULATED-NOT-A-TX-'+i.digest[:24]
            i.state='SIGNED';return i.sim_tx_ref
    def simulate_dispatch(self,i:Intent,response_lost:bool=False)->str:
        with self.lock:
            if i.state not in ['SIGNED','BROADCAST_UNKNOWN','BROADCAST']:raise ContractError('STATE_CONFLICT')
            assert i.sim_tx_ref is not None
            i.dispatch_attempts+=1;i.state='BROADCAST_UNKNOWN' if response_lost else 'BROADCAST'
            return i.sim_tx_ref
    def cancel(self,i:Intent)->None:
        with self.lock:
            if i.state in ['PREPARED','AUTHORIZED','RESERVED']:
                if self.holds.pop(i.digest,None) is not None:self.action_count-=1
                i.state='CANCELED';return
            if i.state=='CANCELED':return
            raise ContractError('RECONCILIATION_REQUIRED')
    def simulate_confirm(self,i:Intent,actual_network_fee:int)->None:
        with self.lock:
            if i.state=='CONFIRMED':return
            if i.state not in ['BROADCAST','BROADCAST_UNKNOWN']:raise ContractError('STATE_CONFLICT')
            a=i.body['amounts'];p=atoms(a['principal_atoms'])
            if actual_network_fee<0 or actual_network_fee>atoms(a['network_fee_cap_atoms']):raise ContractError('FEE_CAP')
            fee=actual_network_fee+atoms(a['service_fee_atoms'])+atoms(a['tax_atoms'])
            self.holds.pop(i.digest);self.balance-=p+fee;self.consumed_principal+=p
            self.consumed_fees+=fee;self.exposure+=p;i.charged=p+fee;i.state='CONFIRMED'
    def simulate_reorg(self,i:Intent)->None:
        with self.lock:
            if i.state!='CONFIRMED':raise ContractError('STATE_CONFLICT')
            i.state='CONFIRMATION_REVERTED'
            # Deliberately no balance or lifetime-capacity restoration.
    def simulate_refund(self,i:Intent,*,eligible:bool)->None:
        with self.lock:
            if not eligible:raise ContractError('REFUND_NOT_ELIGIBLE')
            if i.state=='REFUNDED':return
            if i.state!='CONFIRMED':raise ContractError('RECONCILIATION_REQUIRED')
            p=atoms(i.body['amounts']['principal_atoms']);self.balance+=p;self.exposure-=p
            i.refunded=True;i.state='REFUNDED'
    def summary(self)->dict[str,Any]:
        with self.lock:
            return {'evidence':self.evidence,'balance':self.balance,'available':self.available,
                    'held':sum(self.holds.values()),'committed_exposure':self.exposure,
                    'lifetime_principal':self.consumed_principal,'lifetime_fees':self.consumed_fees,
                    'native_transactions':0,'runtime_executions':0}
