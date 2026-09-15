"""Executable specification fixtures only; NOT BTX wallet/consensus/crypto code.

No signatures, network access, transaction broadcast or model execution occur here.
Production MUST use BTX script/signature and authorization implementations.
"""
from __future__ import annotations
from dataclasses import dataclass
from decimal import Decimal
import hashlib,json,re,struct,threading
from typing import Any
MAX_MONEY=21_000_000*100_000_000
MAX_HEIGHT=499_999_999
DOMAINS={name:(f'BTX/{name}/v1' if name!='ModelSearchRecordV2' else 'BTX/ModelSearchRecord/v2').encode()+b'\x00' for name in ['BountyTerms','EvaluationSpec','FundingRound','Submission','EvaluationReport','AwardProposal','ModelSearchRecordV2']}
DOMAINS.update({name: f'BTX/{name}/v1'.encode()+b'\x00' for name in ['CouncilAppointment', 'SubmissionCommitment', 'AcceptanceCertificate', 'Challenge', 'AwardPolicyApproval']})
class ContractError(ValueError): pass

def atoms(value:str)->int:
    if not isinstance(value,str) or not re.fullmatch(r'0|[1-9][0-9]*',value):raise ContractError('noncanonical atoms')
    n=int(value)
    if n>MAX_MONEY:raise ContractError('MoneyRange')
    return n

def _u32(n:int)->bytes:
    if not 0<=n<=0xffffffff:raise ContractError('length overflow')
    return struct.pack('<I',n)

def canonical(value:Any, depth:int=0)->bytes:
    """Tagged bounded tree encoding; ASCII field names, exact UTF-8 string values."""
    if depth>16:raise ContractError('depth limit')
    if value is None:return b'\x00'
    if value is False:return b'\x01'
    if value is True:return b'\x02'
    if isinstance(value,int):
        if not 0<=value<=0xffffffffffffffff:raise ContractError('uint64 range')
        return b'\x03'+struct.pack('<Q',value)
    if isinstance(value,str):
        try:b=value.encode('utf-8',errors='strict')
        except UnicodeError as e:raise ContractError('invalid UTF-8/surrogate') from e
        if len(b)>8192:raise ContractError('string byte limit')
        return b'\x04'+_u32(len(b))+b
    if isinstance(value,list):
        if len(value)>1024:raise ContractError('array bound')
        return b'\x05'+_u32(len(value))+b''.join(canonical(x,depth+1) for x in value)
    if isinstance(value,dict):
        if len(value)>128:raise ContractError('object bound')
        if any(not isinstance(k,str) or not re.fullmatch('[a-z][a-z0-9_]{0,63}',k) for k in value):raise ContractError('ASCII field name required')
        return b'\x06'+_u32(len(value))+b''.join(canonical(k,depth+1)+canonical(value[k],depth+1) for k in sorted(value))
    raise ContractError('unsupported type; floats/bytes not accepted')

def preimage(body:dict)->bytes:
    allowed={'envelope_version','record_type','network_id','signer_id','public_key_hex','delegation_id','payload'}
    if set(body)!=allowed:raise ContractError('body fields mismatch')
    if body['envelope_version']!=1:raise ContractError('envelope version')
    if body['record_type'] not in DOMAINS:raise ContractError('record type')
    if not re.fullmatch('[0-9a-f]{64}',body['network_id']):raise ContractError('network id')
    raw=DOMAINS[body['record_type']]+bytes.fromhex(body['network_id'])+canonical(body)
    if len(raw)>262144:raise ContractError('envelope bound')
    return raw

def digest(body:dict)->str:return hashlib.sha384(preimage(body)).hexdigest()

def strict_json(raw:str)->Any:
    def pairs(items):
        out={}
        for k,v in items:
            if k in out:raise ContractError('duplicate JSON key')
            out[k]=v
        return out
    def no_float(_):raise ContractError('floating JSON number forbidden')
    return json.loads(raw,object_pairs_hook=pairs,parse_float=no_float,parse_constant=no_float)

def funding_view(target:str,pledged:str,confirmed:str|None)->dict:
    t,p=atoms(target),atoms(pledged)
    if t<=0:raise ContractError('positive target required')
    if confirmed is None:return {'target_atoms':target,'pledged_atoms':pledged,'confirmed_atoms':None,'remaining_atoms':None,'funding_progress_known':False,'funded_bps':None}
    c=atoms(confirmed)
    return {'target_atoms':target,'pledged_atoms':pledged,'confirmed_atoms':confirmed,'remaining_atoms':str(max(0,t-c)),'funding_progress_known':True,'funded_bps':min(10000,c*10000//t)}

def eligible(principal:str,frozen_total:str,min_bps:int)->bool:
    p,t=atoms(principal),atoms(frozen_total)
    if t<=0 or p>t or not 0<=min_bps<=10000:raise ContractError('eligibility range')
    return p*10000>=t*min_bps

def validate_timeline(funding:int,submission:int,evaluation:int,award:int,last_safe:int,refund:int,confirmations:int,margin:int)->None:
    vals=[funding,submission,evaluation,award,last_safe,refund]
    if any(type(v) is not int or v<1 or v>MAX_HEIGHT for v in vals):raise ContractError('height range')
    if not funding<submission<evaluation<=award<=last_safe<refund:raise ContractError('timeline ordering')
    if confirmations<1 or margin<1 or last_safe+confirmations+margin>=refund:raise ContractError('claim margin')

def council_shape(keys:list[str],threshold:int)->bool:
    if not 1<=len(keys)<=8 or not 1<=threshold<=len(keys):raise ContractError('council size/threshold')
    if len(set(keys))!=len(keys):raise ContractError('duplicate council key')
    return True

@dataclass(frozen=True)
class RefundLineage:
    lot_id:str
    refund_key:str
    refund_height:int
    principal:int

def stage(original:RefundLineage,refund_key:str,refund_height:int,principal:int)->RefundLineage:
    if refund_key!=original.refund_key:raise ContractError('refund substitution')
    if refund_height>original.refund_height:raise ContractError('refund extension')
    if principal!=original.principal:raise ContractError('principal change')
    return RefundLineage(original.lot_id,refund_key,refund_height,principal)

@dataclass
class ObservationState:
    confirmed_funding:int=0
    secret_known:bool=False
    def observe_secret(self):self.secret_known=True
    def reorg_funding(self):self.confirmed_funding=0

class MandateBudget:
    """Concurrency/idempotency example. Not an actual wallet authorization service."""
    def __init__(self,total:int,per_action:int):
        self.total=total;self.per_action=per_action;self.used=0;self.revoked=False;self._req={};self._lock=threading.Lock()
    def reserve(self,key:str,amount:int)->int:
        with self._lock:
            if key in self._req:
                if self._req[key]!=amount:raise ContractError('idempotency conflict')
                return amount
            if self.revoked:raise ContractError('revoked')
            if amount<=0 or amount>self.per_action or self.used+amount>self.total:raise ContractError('budget exhausted')
            self._req[key]=amount;self.used+=amount;return amount
    def revoke(self):
        with self._lock:self.revoked=True

def dedupe_principal(lots:list[tuple[str,int]])->int:
    values={}
    for outpoint,amount in lots:
        if amount<0 or amount>MAX_MONEY:raise ContractError('MoneyRange')
        if outpoint in values and values[outpoint]!=amount:raise ContractError('conflicting outpoint amount')
        values[outpoint]=amount
    total=sum(values.values())
    if total>MAX_MONEY:raise ContractError('total MoneyRange')
    return total

def allocate_fee_reserve(reserves:list[int],fee:int)->tuple[list[int],list[int]]:
    if any(x<0 for x in reserves) or fee<0 or fee>sum(reserves):raise ContractError('reserve exceeded')
    total=sum(reserves)
    if not total:return [0]*len(reserves),list(reserves)
    charges=[fee*x//total for x in reserves]
    left=fee-sum(charges)
    order=sorted(range(len(reserves)),key=lambda i:(-(fee*reserves[i]%total),i))
    for i in order[:left]:charges[i]+=1
    return charges,[r-c for r,c in zip(reserves,charges)]
