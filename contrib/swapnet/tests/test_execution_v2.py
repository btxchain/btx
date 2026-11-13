"""Deterministic adversarial ledger tests, NOT a real-chain qualification claim."""
from dataclasses import asdict
import hashlib
import os
import json
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from swapnet.store import Store
from swapnet.journal import Journal
from swapnet.authorization import Authority,Principal,PeerPrincipal
from swapnet.coordinator import Coordinator
from swapnet.vault import ForeignKeyVault
from swapnet.quote import Quote
from swapnet.policy import Mandate,SafetyPolicy,ChainClock
from swapnet.machine import LegObservation
from swapnet.drivers import Report,Prepared
from swapnet.canonical import digest,atoms
from swapnet.errors import SwapError

NETWORK='11'*32
A='btx:'+NETWORK+':0:native'
B='btc:'+'22'*32+':0:native'

class Time:
    def __init__(self):self.n=1_900_000_000
    def __call__(self):return self.n
class Identity:
    keys={}
    def __init__(self,name):
        self.name=name;self.network=NETWORK
        self.key=Ed25519PrivateKey.generate();Identity.keys[name]=self.key.public_key()
    def address(self):return self.name
    def sign(self,message):return self.key.sign(message.encode()).hex()
    def verify(self,address,signature,message):
        try:Identity.keys[address].verify(bytes.fromhex(signature),message.encode());return True
        except Exception:return False
class Ledger:
    def __init__(self,asset,time):self.asset=asset;self.time=time;self.records={};self.transactions={};self.height=100;self.n=0
    def mine(self,count=1):
        self.height+=count
        for r in self.records.values():r['confirmations']+=count
    def rollback_spend(self):
        for r in self.records.values():r['state']='locked';r['confirmations']=3;r['preimage']=None
class Driver:
    def __init__(self,ledger,name):self.ledger=ledger;self.name=name;self.asset=ledger.asset;self.family=self.asset.split(':')[0];self.key_n=0
    def ready(self):return True
    def inventory(self):return 10**12
    def clock(self):return ChainClock(self.family,self.ledger.height,self.ledger.time(),self.ledger.time(),1,1)
    def new_key(self,role):
        self.key_n+=1
        return {'public':self.name+role+str(self.key_n),'handle':self.name+role+str(self.key_n),
                'payout':self.name+'-'+role+'-payout','role':role}
    def commitment(self,h,c,r,t):return hashlib.sha256((h+c+r+str(t)).encode()).hexdigest()
    def verify_terms(self,t):
        assert t.lock_commitment==self.commitment(t.hashlock,t.claim_key,t.refund_key,t.lock_value)
        return {'script_pubkey':t.lock_commitment}
    def watch_terms(self,t,local_key=None):return self.verify_terms(t)
    def _tx(self,kind,terms,ref=None,secret=None,fee='10'):
        raw=json.dumps({'kind':kind,'terms':asdict(terms),'ref':ref,'secret':secret,'fee':fee},sort_keys=True).encode().hex()
        txid=hashlib.sha256(bytes.fromhex(raw)).hexdigest()
        return Prepared(txid,raw,ref or {'txid':txid,'vout':0},fee,{})
    def prepare_funding(self,sid,t,key,rid,maxfee):return self._tx('fund',t)
    def prepare_refund(self,sid,t,ref,key,fee_atoms=None):return self._tx('refund',t,ref,fee=fee_atoms or '10')
    def prepare_claim_template(self,sid,t,ref,key,fee_atoms=None):return {'terms':asdict(t),'reference':ref,'fee_atoms':fee_atoms or '10'}
    def finish_claim(self,t,ref,template,secret):return self._tx('claim',t,ref,secret.hex(),template['fee_atoms'])
    def has_transaction(self,txid):return txid in self.ledger.transactions
    def broadcast(self,raw):
        tx=json.loads(bytes.fromhex(raw));txid=hashlib.sha256(bytes.fromhex(raw)).hexdigest()
        if txid in self.ledger.transactions:return txid
        if tx['kind']=='fund':
            self.ledger.records[txid]={'terms':tx['terms'],'state':'locked','confirmations':0,'preimage':None}
        else:
            record=self.ledger.records[tx['ref']['txid']]
            if record['state']!='locked':raise SwapError('ALREADY_SPENT','Contract has been spent')
            if tx['kind']=='refund':
                if self.ledger.height<tx['terms']['lock_value']:raise SwapError('REFUND_EARLY','Not mature')
                record['state']='refunded'
            else:
                assert hashlib.sha256(bytes.fromhex(tx['secret'])).hexdigest()==tx['terms']['hashlock']
                record['state']='claimed';record['preimage']=tx['secret']
            record['confirmations']=0
        self.ledger.transactions[txid]=raw;return txid
    def observe(self,t,ref):
        if not ref or ref['txid'] not in self.ledger.records:return Report(LegObservation(observed_at=self.ledger.time()),self.clock())
        r=self.ledger.records[ref['txid']];exact=r['terms']==asdict(t)
        return Report(LegObservation(True,exact,True,r['confirmations'],False,r['state']=='claimed',r['state']=='refunded',not exact,self.ledger.time()),
                      self.clock(),r['preimage'])

class Pair:
    def __init__(self,path):
        self.path=path;self.time=Time();self.a=Ledger(A,self.time);self.b=Ledger(B,self.time);self.queue=[];self.nodes={}
        self.identities={n:Identity(n) for n in ('alice','bob')}
        for n in self.identities:self.open(n)
    def open(self,n):
        folder=self.path/n;folder.mkdir(mode=0o700,exist_ok=True)
        store=Store(folder/'state.db');j=Journal(store);auth=Authority(store,j,self.time)
        v=ForeignKeyVault(folder/'vault.json',b'0123456789abcdef0123456789abcdef')
        c=Coordinator(j,auth,{A:Driver(self.a,n),B:Driver(self.b,n)},self.identities[n],v,
                      lambda peer,kind,sid,body:self.queue.append((n,peer,kind,sid,body)),clock=self.time,
                      policy=SafetyPolicy(btx_confirmations=2,btc_confirmations=2,settlement_margin_seconds=10,reveal_margin_seconds=10))
        self.nodes[n]=(store,j,auth,c)
    def close(self,n):self.nodes[n][0].close()
    def restart(self,n):self.close(n);self.open(n)
    def mandate(self,n,asset,total='10000000'):
        m=Mandate(n,asset,total,'100000','1000',self.time()+100000,'33'*32)
        return self.nodes[n][2].install(Principal(n,True),asdict(m))
    def start(self):
        ai=self.mandate('alice',A);bi=self.mandate('bob',B)
        rfq={'network':NETWORK,'requester':digest('BTX/SWAPNET/REQUESTER/2',{'identity':'alice','nonce':'44'*32}),
             'sell_asset':A,'buy_asset':B,'sell_atoms':'10000','nonce':'44'*32,'issued_at':self.time(),'expires_at':self.time()+120}
        q=Quote(NETWORK,'bob',rfq['requester'],'55'*32,1,A,B,'10000','20000','10','100',self.time(),self.time()+120)
        env={'quote':asdict(q),'signature':self.identities['bob'].sign(q.signing_message)}
        self.market={'principal':'bob','wallet':'','mandate_id':bi,'max_local_fee_atoms':'500','refund_fee_atoms':'100','claim_fee_atoms':'100',
                     'market':{'sell_asset':A,'buy_asset':B,'numerator':'2','denominator':'1','maker_fee_atoms':'10',
                               'max_receive_network_fee_atoms':'100','max_input_atoms':'100000','expires_at':self.time()+10000}}
        self.sid=self.nodes['alice'][3].start(Principal('alice'),env,rfq,ai,'500','100') ['swap_id']
        return self.sid
    def deliver(self):
        count=0
        while self.queue:
            sender,peer,kind,sid,body=self.queue.pop(0);c=self.nodes[peer][3]
            if kind=='proposal':c.receive_proposal(sender,sid,body,self.market)
            elif kind=='agreement':c.receive_agreement(sender,sid,body)
            elif kind=='commit':c.receive_commit(sender,sid,body)
            elif kind=='funded':c.receive_reference(sender,sid,body)
            elif kind=='cancel':c.receive_cancel(sender,sid,body)
            count+=1;assert count<100
    def step(self,mine=True):
        self.deliver()
        for n in ('alice','bob'):self.nodes[n][3].tick()
        self.deliver()
        if mine:self.a.mine();self.b.mine()
        self.time.n+=1
    def state(self,n):return self.nodes[n][1].load(self.sid)[1]

@pytest.fixture
def pair(tmp_path):
    p=Pair(tmp_path)
    yield p
    for n in p.nodes:p.close(n)

def test_full_two_party_settlement(pair):
    pair.start()
    for _ in range(18):pair.step()
    assert pair.state('alice')['stage']=='complete'
    assert pair.state('bob')['stage']=='complete'
    assert pair.state('alice')['secret_exposed'] and pair.state('bob')['secret_exposed']
    assert len(pair.a.records)==len(pair.b.records)==1

def test_restart_each_phase_no_double_funding(pair):
    pair.start()
    for _ in range(18):
        pair.step();pair.restart('alice');pair.restart('bob')
    assert pair.state('alice')['stage']=='complete'
    assert pair.state('bob')['stage']=='complete'
    assert len(pair.a.records)==len(pair.b.records)==1

def test_peer_cannot_install_authorization(pair):
    with pytest.raises(SwapError,match='OWNER_REQUIRED'):
        pair.nodes['alice'][2].install(PeerPrincipal('attacker'),{})

def test_timeout_refunds_without_counterparty_funding(pair):
    pair.start();pair.deliver()
    c=pair.nodes['alice'][3]
    c.tick();c.tick();pair.a.mine(3)
    assert pair.state('alice')['funding_broadcast']
    height=pair.state('alice')['agreement']['long_leg']['lock_value']
    pair.a.height=height;pair.b.height+=1
    for _ in range(4):c.tick();pair.a.mine();pair.time.n+=1
    assert pair.state('alice')['stage']=='refunded'
    assert not pair.state('alice')['secret_exposed']

def test_mutated_payout_rejected_before_signature(pair):
    pair.start()
    sender,peer,kind,sid,body=pair.queue.pop(0)
    pair.nodes['bob'][3].receive_proposal(sender,sid,body,pair.market)
    sender,peer,kind,sid,body=pair.queue.pop(0)
    body['agreement']['short_leg']['payout']='attacker'
    with pytest.raises(SwapError,match='PAYOUT_CHANGED'):
        pair.nodes['alice'][3].receive_agreement(sender,sid,body)
    assert not pair.a.records

def test_no_early_refund(pair):
    sid=pair.start();pair.step();pair.step()
    with pytest.raises(SwapError,match='REFUND_EARLY'):
        pair.nodes['alice'][3].request_refund(Principal('alice'),sid)

def test_foreign_user_cannot_read_session(pair):
    sid=pair.start()
    with pytest.raises(SwapError,match='FORBIDDEN'):
        pair.nodes['alice'][3].get(Principal('other'),sid)

def test_reorg_never_rehides_secret(pair):
    pair.start()
    for _ in range(16):pair.step()
    pair.b.rollback_spend();pair.nodes['alice'][3].tick()
    assert pair.state('alice')['secret_exposed'] is True
    pair.restart('alice')
    assert pair.state('alice')['secret_exposed'] is True

def test_journal_outbox_and_operation_roundtrip(pair):
    sid=pair.start();pair.step();pair.step()
    journal=pair.nodes['alice'][1]
    ops=journal.operations(sid,private=True)
    assert {o['kind'] for o in ops}=={'fund','refund'}
    assert all('raw' not in o for o in journal.operations(sid))
    assert journal.store.verify_audit()
