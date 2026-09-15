"""BTX Model Network v1.1 reference only. No networking, signing or wallet access.

Tests exercise these new codecs and local policy examples, not BTX consensus,
production TLS, operating-system URI registration, or adversarial network fairness.
Python 3.10+, standard library only. Locally authored implementation of the
specified Bech32m checksum; BIP350 and BTX's existing codec are implementation
references. See the specification for the public format and policy boundaries.
"""
from __future__ import annotations
from dataclasses import dataclass
import hashlib
import math
import re
from collections import defaultdict
from typing import Iterable

ALPHABET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
GENERATORS = (0x3b6a57b2,0x26508e6d,0x1ea119fa,0x3d4233dd,0x2a1462b3)
BECH32M = 0x2bc830a3
RESOURCE_VERSION = 1
KINDS = {0:'MODEL',1:'ARTIFACT',2:'COLLECTION',3:'IDENTITY',4:'RELEASE',5:'POLICY_BUNDLE',6:'CIRCLE',7:'ALIAS',8:'PROVIDER'}
MIB = 1 << 20
DAY = 86400
MAX_MONEY = 21_000_000 * 100_000_000

def d384(label: str, body: bytes) -> bytes:
    name = label.encode('ascii')
    if not 1 <= len(name) <= 255:
        raise ValueError('invalid hash domain')
    return hashlib.sha384(len(name).to_bytes(2,'little') + name + len(body).to_bytes(8,'little') + body).digest()

def polymod(values: Iterable[int]) -> int:
    chk = 1
    for value in values:
        if not 0 <= value < 32: raise ValueError('invalid 5-bit value')
        top = chk >> 25
        chk = ((chk & 0x1ffffff) << 5) ^ value
        for i, gen in enumerate(GENERATORS):
            if (top >> i) & 1: chk ^= gen
    return chk

def hrp_expand(hrp: str) -> list[int]:
    return [ord(c)>>5 for c in hrp] + [0] + [ord(c)&31 for c in hrp]

def convertbits(data: Iterable[int], frombits: int, tobits: int, pad: bool) -> list[int]:
    acc=0; bits=0; result=[]; mask=(1<<tobits)-1
    for value in data:
        if not 0 <= value < (1 << frombits): raise ValueError('invalid input value')
        acc = ((acc << frombits) | value) & ((1 << (frombits+tobits-1))-1)
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            result.append((acc >> bits)&mask)
    if pad:
        if bits: result.append((acc << (tobits-bits))&mask)
    elif bits >= frombits or ((acc << (tobits-bits))&mask):
        raise ValueError('noncanonical residual bits')
    return result

def raw_token(version: int, kind: int, digest: bytes) -> str:
    """Low-level vector helper; production encode_resource checks the registry."""
    if len(digest)!=48: raise ValueError('digest must contain 48 bytes')
    data=[version,kind]+convertbits(digest,8,5,True)
    chk=polymod(hrp_expand('btx')+data+[0]*6)^BECH32M
    return ''.join(ALPHABET[x] for x in data+[(chk>>(5*(5-i)))&31 for i in range(6)])

def encode_resource(kind: int, digest: bytes) -> str:
    if kind not in KINDS: raise ValueError('unsupported resource type')
    return 'btx://'+raw_token(RESOURCE_VERSION,kind,digest)

@dataclass(frozen=True)
class Resource:
    kind: int
    digest: bytes
    @property
    def uri(self) -> str: return encode_resource(self.kind,self.digest)

def decode_resource(text: str) -> Resource:
    if not isinstance(text,str) or len(text)>512 or not text.isascii():
        raise ValueError('invalid URI input')
    # Raw tokens and btx: aliases are accepted only at explicit local inputs.
    if text[:6].lower()=='btx://': token=text[6:]
    elif text[:4].lower()=='btx:': token=text[4:]
    else: token=text
    if token.endswith('/'):
        token=token[:-1]  # one platform-appended empty path only
    if len(token)!=85 or (token!=token.lower() and token!=token.upper()):
        raise ValueError('invalid token length or mixed case')
    token=token.lower()
    if any(c not in ALPHABET for c in token): raise ValueError('invalid token character')
    values=[ALPHABET.index(c) for c in token]
    if polymod(hrp_expand('btx')+values)!=BECH32M: raise ValueError('checksum mismatch')
    data=values[:-6]
    if data[0]!=RESOURCE_VERSION: raise ValueError('unsupported resource version')
    if data[1] not in KINDS: raise ValueError('unsupported resource type')
    digest=bytes(convertbits(data[2:],5,8,False))
    if len(digest)!=48: raise ValueError('invalid digest length')
    return Resource(data[1],digest)

def bridge_path(uri: str, origin: str='https://bridge.example.org') -> str:
    r=decode_resource(uri)
    if not re.fullmatch(r'https://[a-z0-9.-]+(?::[0-9]+)?',origin):
        raise ValueError('bridge origin must be configured HTTPS origin')
    return origin+'/'+r.uri[6:]

def split_bridge_host(uri: str, suffix: str='bridge.example.org') -> str:
    if not re.fullmatch('[a-z0-9.-]+',suffix):raise ValueError('invalid bridge suffix')
    t=decode_resource(uri).uri[6:]
    return t[:42]+'.'+t[42:]+'.'+suffix

def compact_size(n: int) -> bytes:
    if isinstance(n,bool) or not isinstance(n,int) or not 0<=n<1<<64:raise ValueError('invalid CompactSize')
    if n<253:return bytes([n])
    if n<=65535:return b'\xfd'+n.to_bytes(2,'little')
    if n<=0xffffffff:return b'\xfe'+n.to_bytes(4,'little')
    return b'\xff'+n.to_bytes(8,'little')

class Reader:
    def __init__(self,b:bytes,max_size:int=65536):
        if len(b)>max_size:raise ValueError('object exceeds size limit')
        self.b=b;self.i=0
    def take(self,n:int)->bytes:
        if n<0 or self.i+n>len(self.b):raise ValueError('truncated object')
        out=self.b[self.i:self.i+n];self.i+=n;return out
    def size(self,max_n:int)->int:
        p=self.take(1)[0]
        if p<253:n=p
        else:
            width={253:2,254:4,255:8}[p];n=int.from_bytes(self.take(width),'little')
            if n<({253:253,254:65536,255:4294967296}[p]):raise ValueError('nonminimal length')
        if n>max_n:raise ValueError('length exceeds cap')
        return n

# Ordered field definitions are also supplied in record-layouts.json.
COMMON=[('ext_version','u16'),('network','hex32'),('signer_role','u8'),('signer_id','hex48'),('sequence','u64'),('issued_at','u64'),('expires_at','u64')]
LAYOUTS={
 16:('IdentityCard',[('display_name','str96'),('description','str1024')]),
 17:('ServiceDelegation',[('delegate_pubkey','bytes1312'),('scopes','u32'),('all_models','bool'),('model_scope',('vec','hex48',64))]),
 18:('Revocation',[('target_kind','u8'),('target_id','hex48'),('reason_code','u16')]),
 19:('Collection',[('title','str96'),('description','str1024'),('entries',('vec',('struct',[('model_id','hex48'),('priority','u8'),('retention_days','u16')]),512))]),
 20:('AliasRecord',[('slug','str32'),('active','bool'),('target_kind','u8'),('target_id','hex48'),('previous_record_id','hex48')]),
 21:('PolicyBundle',[('title','str96'),('recommendations',('vec',('struct',[('target_kind','u8'),('target_id','hex48'),('action','u8'),('ttl_seconds','u32'),('reason','str192')]),128))]),
 22:('PreservationCircle',[('title','str96'),('description','str1024'),('collection_id','hex48'),('target_observed_groups','u8'),('suggested_storage_bytes','u64'),('suggested_lease_seconds','u32')]),
 23:('FreeGrant',[('transfer_id','hex32'),('buyer_id','hex48'),('model_id','hex48'),('artifact_id','hex48'),('file_index','u32'),('first_piece','u32'),('piece_count','u32'),('maximum_bytes','u64'),('grant_nonce','hex32'),('queue_class','u8')]),
 24:('ServiceReceipt',[('receipt_kind','u8'),('transfer_id','hex32'),('provider_id','hex48'),('buyer_id','hex48'),('model_id','hex48'),('artifact_id','hex48'),('file_index','u32'),('first_piece','u32'),('piece_count','u32'),('verified_bytes','u64'),('outcome','u8'),('previous_receipt_id','hex48')])}

def encode_value(t,v)->bytes:
    if isinstance(t,tuple):
        if t[0]=='vec':
            if not isinstance(v,list) or len(v)>t[2]:raise ValueError('vector cap')
            return compact_size(len(v))+b''.join(encode_value(t[1],i) for i in v)
        if t[0]=='struct':return encode_fields(t[1],v)
    if t=='bool':
        if type(v)!=bool:raise ValueError('invalid bool')
        return bytes([int(v)])
    if t.startswith('u'):
        bits=int(t[1:])
        if type(v)!=int or not 0<=v<(1<<bits):raise ValueError('integer out of range')
        return v.to_bytes(bits//8,'little')
    if t.startswith('hex'):
        n=int(t[3:])
        if not isinstance(v,str) or not re.fullmatch('[0-9a-f]{'+str(2*n)+'}',v):raise ValueError('invalid fixed hex')
        return bytes.fromhex(v)
    if t.startswith('str'):
        b=v.encode('utf-8');n=int(t[3:])
        if len(b)>n or '\x00' in v:raise ValueError('string cap or NUL')
        return compact_size(len(b))+b
    if t.startswith('bytes'):
        n=int(t[5:]);b=bytes.fromhex(v)
        if len(b)!=n or v!=v.lower():raise ValueError('byte length')
        return compact_size(n)+b
    raise ValueError('unknown type')

def encode_fields(fields,v)->bytes:
    if set(v)!={f for f,_ in fields}:raise ValueError('extra/missing field')
    return b''.join(encode_value(t,v[f]) for f,t in fields)

def decode_value(t,r):
    if isinstance(t,tuple):
        if t[0]=='vec':return [decode_value(t[1],r) for _ in range(r.size(t[2]))]
        if t[0]=='struct':return {f:decode_value(s,r) for f,s in t[1]}
    if t=='bool':
        b=r.take(1)[0]
        if b>1:raise ValueError('invalid bool')
        return bool(b)
    if t.startswith('u'):return int.from_bytes(r.take(int(t[1:])//8),'little')
    if t.startswith('hex'):return r.take(int(t[3:])).hex()
    if t.startswith('str'):
        s=r.take(r.size(int(t[3:]))).decode('utf-8')
        if '\x00' in s:raise ValueError('NUL')
        return s
    if t.startswith('bytes'):
        n=int(t[5:])
        if r.size(n)!=n:raise ValueError('fixed byte string wrong length')
        return r.take(n).hex()
    raise ValueError('unknown type')

def check_record(kind:int,v:dict)->None:
    if kind not in LAYOUTS or v['ext_version']!=257:raise ValueError('version/type')
    expected_role=0 if kind in (23,24) else 1
    if v['signer_role']!=expected_role:raise ValueError('wrong signer role')
    if v['sequence']<1:raise ValueError('sequence must be positive')
    if kind!=18 and v['expires_at'] and v['expires_at']<=v['issued_at']:raise ValueError('invalid expiry')
    if kind in (17,20,21,23,24) and not v['expires_at']:raise ValueError('expiry required')
    if kind==17:
        if not 0<v['scopes']<=31:raise ValueError('delegation scope')
        if v['all_models']!= (len(v['model_scope'])==0):raise ValueError('ambiguous model scope')
        if v['model_scope']!=sorted(set(v['model_scope'])):raise ValueError('model scope order')
        if v['expires_at']-v['issued_at']>7*DAY:raise ValueError('delegation too long')
    if kind==18 and (v['target_kind'] not in (1,2) or v['expires_at']!=0):raise ValueError('revocation shape')
    if kind==19:
        ids=[i['model_id'] for i in v['entries']]
        if not ids or ids!=sorted(set(ids)):raise ValueError('collection order')
        if any(not 1<=i['priority']<=5 or i['retention_days']>3650 for i in v['entries']):raise ValueError('entry policy')
    if kind==20:
        if not re.fullmatch('[a-z0-9][a-z0-9-]{0,31}',v['slug']):raise ValueError('alias slug')
        if v['active'] and v['target_kind'] not in (0,2,4,5,6):raise ValueError('alias target')
        if not v['active'] and (v['target_kind']!=255 or v['target_id']!='00'*48):raise ValueError('alias tombstone')
    if kind==21:
        if not v['recommendations']:raise ValueError('empty policy')
        tuples=[(x['target_kind'],x['target_id'],x['action']) for x in v['recommendations']]
        if tuples!=sorted(set(tuples)):raise ValueError('policy order')
        for x in v['recommendations']:
            if x['target_kind'] not in (0,1,2,3,8) or x['action'] not in (1,2,3,4) or not 1<=x['ttl_seconds']<=30*DAY:raise ValueError('policy entry')
            if (x['action']==1 and x['target_kind']!=3) or (x['action']==2 and x['target_kind']!=8):raise ValueError('policy action target')
    if kind==22 and (not 1<=v['target_observed_groups']<=16 or v['suggested_lease_seconds']>7*DAY):raise ValueError('circle bound')
    if kind==23:
        if v['piece_count']==0 or v['maximum_bytes']==0 or v['queue_class'] not in (0,1,2):raise ValueError('free range')
        if v['expires_at']-v['issued_at']>600:raise ValueError('free grant too long')
    if kind==24:
        if v['receipt_kind'] not in (0,1) or v['outcome'] not in (0,1,2):raise ValueError('receipt enum')
        if v['signer_id'] != v['buyer_id' if v['receipt_kind']==0 else 'provider_id']:raise ValueError('receipt signer')

def encode_record(kind:int,v:dict)->bytes:
    if kind not in LAYOUTS:raise ValueError('unsupported record')
    check_record(kind,v)
    b=encode_fields(COMMON+LAYOUTS[kind][1],v)
    if len(b)>(65536 if kind in (19,21) else 16384):raise ValueError('record body cap')
    return b

def decode_record(kind:int,b:bytes)->dict:
    if kind not in LAYOUTS:raise ValueError('unsupported record')
    r=Reader(b,65536 if kind in (19,21) else 16384)
    v={f:decode_value(t,r) for f,t in COMMON+LAYOUTS[kind][1]}
    if r.i!=len(b):raise ValueError('trailing bytes')
    check_record(kind,v)
    return v

def record_id(kind:int,v:dict)->bytes:
    return d384('BTX/'+LAYOUTS[kind][0]+'/v1.1',encode_record(kind,v))

def signing_message(kind:int,v:dict)->bytes:
    return d384('BTX/ModelExtensionSig/v1.1',bytes([kind])+bytes.fromhex(v['network'])+record_id(kind,v))

class ReciprocityLedger:
    """Only locally received needed free chunks produce useful credit."""
    def __init__(self):self.events=[];self.seen=set()
    def received(self,peer:str,artifact:str,file:int,piece:int,nbytes:int,when:int,*,verified:bool,needed:bool,paid:bool,observed_sources:int)->bool:
        if nbytes<=0 or when<0:raise ValueError('invalid observation')
        key=(artifact,file,piece) # local cross-peer dedupe: no reward for replaying another peer's chunk
        if not verified or not needed or paid or key in self.seen:return False
        self.seen.add(key)
        bonus=2 if observed_sources in (1,2) else 1
        self.events.append((peer,nbytes*bonus,when))
        return True
    def effective(self,peer:str,now:int)->int:
        total=0
        for p,b,t in self.events:
            age=max(0,now-t)
            if p==peer and age<28*DAY:total+=b >> (age//(7*DAY))
        return min(total,4<<30)
    def weight(self,peer:str,now:int)->int:
        units=min(64,self.effective(peer,now)//(64*MIB))
        return 1+(3*units)//64

@dataclass(frozen=True)
class PaidPlan:
    price_atoms:int
    fee_atoms:int
    total_eta_s:int|None
    safe:bool=True
    deliverable:bool=True
    requires_release:bool=False

def choose_plan(mode:str,*,free_eta_s:int|None,paid:PaidPlan|None,budget_atoms:int=0,exposure_ok:bool=True,deadline_s:int|None=None,value_per_second_atoms:int=0,approved:bool=False)->str:
    if mode not in ('FREE_ONLY','FREE_FIRST_APPROVAL','FREE_FIRST_BUDGET','EXPLICIT_PAID'):raise ValueError('unknown retrieval mode')
    if any(type(v)!=int or v<0 for v in [budget_atoms,value_per_second_atoms]):raise ValueError('invalid policy amount')
    for duration in (free_eta_s,deadline_s,paid.total_eta_s if paid else None):
        if duration is not None and (type(duration)!=int or duration<0):raise ValueError('invalid ETA/deadline')
    if mode=='FREE_ONLY':return 'FREE' if free_eta_s is not None else 'WAIT_FREE'
    if paid is None or not paid.safe or not paid.deliverable or paid.requires_release:return 'FREE' if free_eta_s is not None else 'WAIT_FREE'
    if any(type(v)!=int or v<0 for v in [paid.price_atoms,paid.fee_atoms]):raise ValueError('bad price')
    cost=paid.price_atoms+paid.fee_atoms
    if cost>MAX_MONEY or not exposure_ok:return 'FREE' if free_eta_s is not None else 'WAIT_FREE'
    if mode=='EXPLICIT_PAID':return 'PAID' if approved and cost<=budget_atoms else 'APPROVAL_REQUIRED'
    t=paid.total_eta_s
    saves=(free_eta_s is not None and t is not None and free_eta_s>t)
    missing=(free_eta_s is None and t is not None)
    deadline_gain=(deadline_s is not None and t is not None and t<=deadline_s and (free_eta_s is None or free_eta_s>deadline_s))
    economical=saves and value_per_second_atoms*(free_eta_s-t)>=cost
    worthwhile=missing or deadline_gain or economical
    if not worthwhile:return 'FREE' if free_eta_s is not None else 'WAIT_FREE'
    if mode=='FREE_FIRST_APPROVAL':return 'PAID' if approved and cost<=budget_atoms else 'APPROVAL_REQUIRED'
    return 'PAID' if cost<=budget_atoms else ('FREE' if free_eta_s is not None else 'WAIT_FREE')

def acl_decision(*,crypto_ok:bool,hard_limit_ok:bool,local_deny:bool=False,quarantined:bool=False,exact_allow:bool=False,subscribed_deny:bool=False,needs_spend:bool=False,budget_approved:bool=False)->str:
    if not crypto_ok:return 'REJECT_CRYPTO'
    if not hard_limit_ok:return 'RETRY_RESOURCE'
    if local_deny:return 'DENY_LOCAL'
    if quarantined:return 'QUARANTINE'
    if subscribed_deny and not exact_allow:return 'DENY_SUBSCRIBED'
    if needs_spend and not budget_approved:return 'REQUIRE_SPEND_APPROVAL'
    return 'ALLOW'

def lane_sequence(backlogs:dict[str,int],quanta:int)->list[str]:
    """Deterministic byte-quantum example of work-conserving 20/60/20 free lanes."""
    b=dict(backlogs);out=[]
    order=['bootstrap','reciprocal','reciprocal','preservation','reciprocal']
    for i in range(quanta):
        wanted=order[i%len(order)]
        eligible=[k for k in order if b.get(k,0)>0]
        if not eligible:break
        k=wanted if b.get(wanted,0)>0 else eligible[0]
        out.append(k);b[k]-=1
    return out
