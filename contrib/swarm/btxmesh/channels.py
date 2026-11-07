"""Executable PAY/1 protocol models and routing math, not native financial exits.

These models expose monotonicity, reservation, expiry and conservation failures.
They MUST NOT be advertised as enforceable L2 channels. Native P2MR construction,
PSBT/ML-DSA signing, interpreter checks, fee recovery and regtest exits are gates.
"""
import hashlib
import heapq
import itertools
from dataclasses import dataclass
from .codec import encode,digest,atoms,integer,fields
from .errors import require,MeshError
from .identity import verify

@dataclass
class MonotonicChannel:
    channel_id:str
    payer:str
    recipient:str
    capacity:int
    fee_reserve:int
    refund_height:int
    close_margin:int=160
    sequence:int=0
    cumulative:int=0
    def offer(self,sequence,cumulative,height):
        integer(sequence,1,2**63-1);integer(cumulative,0,self.capacity)
        require(sequence>self.sequence,'STALE_VOUCHER')
        require(cumulative>=self.cumulative,'DECREASING_PAYMENT')
        require(cumulative+self.fee_reserve<=self.capacity,'CHANNEL_CAPACITY')
        require(height+self.close_margin<self.refund_height,'CHANNEL_DRAINING')
        return {'protocol':'BTX-PAY/1','channel':self.channel_id,'payer':self.payer,'recipient':self.recipient,'sequence':sequence,'cumulative_atoms':str(cumulative),'refund_height':self.refund_height,'fee_reserve_atoms':str(self.fee_reserve),'assurance':'PROTOCOL_MODEL_NOT_NATIVE_CLAIM'}
    def accept(self,body,signature,public_key,height):
        fields(body,{'protocol','channel','payer','recipient','sequence','cumulative_atoms','refund_height','fee_reserve_atoms','assurance'})
        require(verify(public_key,b'BTX/PayVoucherModel/1\x00'+encode(body),signature)==self.payer,'PAYER_SIGNATURE')
        expected=self.offer(body['sequence'],atoms(body['cumulative_atoms']),height)
        require(body==expected,'VOUCHER_BINDING');self.sequence=body['sequence'];self.cumulative=atoms(body['cumulative_atoms'])
        return {'accepted':True,'enforceable':False,'native_transaction':None}

@dataclass(frozen=True)
class Edge:
    id:str
    source:str
    target:str
    liquidity:int
    base_fee:int=0
    ppm_fee:int=0
    cltv_delta:int=160
    active:bool=True
    def __post_init__(self):
        integer(self.liquidity,0,2**63-1);integer(self.base_fee,0,2**63-1);integer(self.ppm_fee,0,1000000);integer(self.cltv_delta,1,6720)
    def fee(self,amount):return self.base_fee+(amount*self.ppm_fee+999999)//1000000


def route(edges,source,destination,amount_atoms,final_expiry,current_height,*,max_hops=5,max_fee_atoms='1000000',max_expiry_delta=6720):
    amount=atoms(amount_atoms);fee_cap=atoms(max_fee_atoms);require(amount>0,'AMOUNT')
    require(final_expiry>current_height,'INVOICE_EXPIRED');integer(max_hops,1,12)
    # Bounded best-first reverse search. State retains its path so fee/CLTV and
    # hop-dependent alternatives are not incorrectly discarded as one vertex cost.
    counter=itertools.count();queue=[(amount,next(counter),0,destination,final_expiry,(),())];scanned=0
    while queue:
        needed,_,hops,node,expiry,path,visited=heapq.heappop(queue);scanned+=1
        require(scanned<=100000,'ROUTE_SEARCH_LIMIT')
        if node==source:
            return {'hops':list(path),'send_atoms':str(needed),'receive_atoms':str(amount),'fee_atoms':str(needed-amount),'incoming_expiry':expiry,'enforcement':'ROUTE_PLAN_ONLY'}
        if hops>=max_hops:continue
        for edge in edges:
            if not edge.active or edge.target!=node or edge.source in visited+(node,):continue
            # The forwarder (edge.source), except the original sender, charges its
            # fee for the outgoing edge. Each hop gets strictly more upstream slack.
            fee=0 if edge.source==source else edge.fee(needed)
            send=needed+fee;incoming=expiry+(edge.cltv_delta if edge.source!=source else 0)
            if needed>edge.liquidity or send-amount>fee_cap or incoming-current_height>max_expiry_delta:continue
            hop={'edge':edge.id,'source':edge.source,'target':node,'forward_atoms':str(needed),'outgoing_expiry':expiry}
            heapq.heappush(queue,(send,next(counter),hops+1,edge.source,incoming,(hop,*path),(*visited,node)))
    raise MeshError('NO_LIQUID_ROUTE')


class ConditionalModel:
    def __init__(self,capacity):self.capacity=capacity;self.settled=0;self.inflight={};self.history={}
    def lock(self,id,amount,payment_hash,expiry,height):
        require(id not in self.inflight and id not in self.history,'HTLC_REPLAY')
        require(isinstance(payment_hash,str) and len(payment_hash)==64,'PAYMENT_HASH');integer(amount,1,self.capacity)
        require(expiry>height and self.settled+sum(x['amount'] for x in self.inflight.values())+amount<=self.capacity,'HTLC_CAPACITY_OR_EXPIRY')
        self.inflight[id]={'amount':amount,'hash':payment_hash,'expiry':expiry}
    def resolve(self,id,preimage,height):
        p=self.inflight.get(id);require(p is not None,'HTLC_UNKNOWN')
        require(isinstance(preimage,bytes) and len(preimage)==32 and hashlib.sha256(preimage).hexdigest()==p['hash'],'PREIMAGE')
        require(height<p['expiry'],'HTLC_EXPIRED')
        self.settled+=p['amount'];self.history[id]='FULFILLED';del self.inflight[id]
    def expire(self,id,height):
        p=self.inflight.get(id);require(p is not None and height>=p['expiry'],'HTLC_NOT_EXPIRED')
        self.history[id]='EXPIRED';del self.inflight[id]
    def conserved(self):return self.settled+sum(x['amount'] for x in self.inflight.values())<=self.capacity


def watchtower_action(channel,observed_state,height,latest_state):
    if observed_state<latest_state:return {'action':'STALE_STATE_ALERT','native_remedy_available':False,'must_not_assume_penalty_enforceability':True}
    if height+channel.close_margin>=channel.refund_height:return {'action':'DRAIN_AND_NOTIFY','native_remedy_available':False}
    return {'action':'OBSERVE','native_remedy_available':False}
