"""Ethereum-specific Keccak, ABI and EIP-1559 codecs plus pinned-contract reader.

SHA3-256 is NOT Keccak-256. HTLC hashlocks nevertheless use SHA-256 on both chains.
Private signing remains in cryptography/OpenSSL or an external signer. The small
public-point arithmetic below is used solely for recovering/verifying a sender.
"""
from dataclasses import dataclass
import hashlib
from .canonical import hex32,integer
from .errors import require,SwapError
from .machine import LegObservation

MASK=(1<<64)-1
RC=[0x0000000000000001,0x0000000000008082,0x800000000000808A,0x8000000080008000,
0x000000000000808B,0x0000000080000001,0x8000000080008081,0x8000000000008009,
0x000000000000008A,0x0000000000000088,0x0000000080008009,0x000000008000000A,
0x000000008000808B,0x800000000000008B,0x8000000000008089,0x8000000000008003,
0x8000000000008002,0x8000000000000080,0x000000000000800A,0x800000008000000A,
0x8000000080008081,0x8000000000008080,0x0000000080000001,0x8000000080008008]
ROT=[[0,36,3,41,18],[1,44,10,45,2],[62,6,43,15,61],[28,55,25,21,56],[27,20,39,8,14]]
def _rot(x,n):return ((x<<n)|(x>>(64-n)))&MASK if n else x

def keccak256(data):
    require(type(data) is bytes,'KECCAK','Expected bytes')
    rate=136;pad=bytearray(data);pad.append(1)
    pad.extend(b'\0'*((-len(pad))%rate));pad[-1]|=0x80
    a=[0]*25
    for offset in range(0,len(pad),rate):
        block=pad[offset:offset+rate]
        for i in range(rate//8):a[i]^=int.from_bytes(block[i*8:i*8+8],'little')
        for rc in RC:
            c=[a[x]^a[x+5]^a[x+10]^a[x+15]^a[x+20] for x in range(5)]
            d=[c[(x-1)%5]^_rot(c[(x+1)%5],1) for x in range(5)]
            for x in range(5):
                for y in range(5):a[x+5*y]^=d[x]
            b=[0]*25
            for x in range(5):
                for y in range(5):b[y+5*((2*x+3*y)%5)]=_rot(a[x+5*y],ROT[x][y])
            for x in range(5):
                for y in range(5):a[x+5*y]=b[x+5*y]^((~b[(x+1)%5+5*y])&b[(x+2)%5+5*y])
            a[0]^=rc
    return b''.join(x.to_bytes(8,'little') for x in a)[:32]

def _be(n):
    require(type(n) is int and 0<=n<1<<256,'UINT256','Invalid uint256')
    return n.to_bytes((n.bit_length()+7)//8,'big')

def rlp(value):
    if type(value) is int:value=_be(value)
    if type(value) is bytes:
        if len(value)==1 and value[0]<128:return value
        if len(value)<=55:return bytes([128+len(value)])+value
        n=_be(len(value));return bytes([183+len(n)])+n+value
    require(type(value) is list,'RLP','Unsupported RLP type')
    payload=b''.join(rlp(x) for x in value)
    if len(payload)<=55:return bytes([192+len(payload)])+payload
    n=_be(len(payload));return bytes([247+len(n)])+n+payload

def decode_rlp(raw):
    require(type(raw) is bytes and len(raw)<=1_000_000,'RLP','Invalid encoded RLP')
    def one(pos,depth):
        require(depth<=16 and pos<len(raw),'RLP','Malformed or excessive RLP')
        p=raw[pos];start=pos;pos+=1
        if p<128:return bytes([p]),pos
        is_list=p>=192
        base=192 if is_list else 128
        if p<base+56:length=p-base
        else:
            n=p-(247 if is_list else 183)
            require(pos+n<=len(raw) and raw[pos]!=0,'RLP','Invalid RLP length')
            length=int.from_bytes(raw[pos:pos+n],'big');pos+=n
            require(length>=56,'RLP','Noncanonical RLP length')
        end=pos+length;require(end<=len(raw),'RLP','RLP truncated')
        if is_list:
            result=[]
            while pos<end:
                child,pos=one(pos,depth+1);result.append(child)
                require(len(result)<=1024 and pos<=end,'RLP','RLP list limit')
            require(pos==end,'RLP','RLP list overflow')
            return result,end
        result=raw[pos:end]
        require(not(len(result)==1 and result[0]<128),'RLP','Noncanonical RLP string')
        return result,end
    obj,end=one(0,0);require(end==len(raw),'RLP','Trailing RLP bytes');return obj

def address_bytes(address):
    require(type(address) is str and len(address)==42 and address.startswith('0x') and address==address.lower(),'EVM_ADDRESS','Canonical lowercase EVM address required')
    try:raw=bytes.fromhex(address[2:])
    except ValueError as e:raise SwapError('EVM_ADDRESS','Invalid address hex') from e
    require(len(raw)==20,'EVM_ADDRESS','Wrong address length');return raw

def address_from_key(key):
    numbers=key.public_key().public_numbers()
    return '0x'+keccak256(numbers.x.to_bytes(32,'big')+numbers.y.to_bytes(32,'big'))[-20:].hex()

def abi_word(value):
    if type(value) is int:return _be(value).rjust(32,b'\0')
    if type(value) is bytes:
        require(len(value) in {20,32},'ABI','Unsupported static bytes size');return value.rjust(32,b'\0')
    raise SwapError('ABI','Unsupported ABI value')

def calldata(signature,*args):return keccak256(signature.encode('ascii'))[:4]+b''.join(abi_word(a) for a in args)

P=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G=(0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
   0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

def _add(a,b):
    if a is None:return b
    if b is None:return a
    x,y=a;u,v=b
    if x==u and (y+v)%P==0:return None
    slope=((3*x*x)*pow(2*y,-1,P) if a==b else (v-y)*pow(u-x,-1,P))%P
    z=(slope*slope-x-u)%P
    return z,(slope*(x-z)-y)%P

def _mul(n,point):
    result=None
    while n:
        if n&1:result=_add(result,point)
        point=_add(point,point);n>>=1
    return result

def recover_address(digest,r,s,parity):
    require(len(digest)==32 and 0<r<N and 0<s<=N//2 and parity in (0,1),'EVM_SIGNATURE','Invalid Ethereum signature')
    x=r;y=pow((x*x*x+7)%P,(P+1)//4,P)
    require((y*y-x*x*x-7)%P==0,'EVM_SIGNATURE','Recovery point is not on curve')
    if y&1!=parity:y=P-y
    point=(x,y)
    require(_mul(N,point) is None,'EVM_SIGNATURE','Invalid recovery point order')
    q=_mul(pow(r,-1,N),_add(_mul(s,point),_mul((-int.from_bytes(digest,'big'))%N,G)))
    require(q is not None,'EVM_SIGNATURE','Recovered infinity')
    return '0x'+keccak256(q[0].to_bytes(32,'big')+q[1].to_bytes(32,'big'))[-20:].hex()

@dataclass(frozen=True)
class Eip1559Transaction:
    chain_id:int
    nonce:int
    priority_fee:int
    max_fee:int
    gas:int
    to:bytes
    value:int
    data:bytes
    def __post_init__(self):
        for x in (self.chain_id,self.nonce,self.priority_fee,self.max_fee,self.gas,self.value):_be(x)
        require(self.chain_id>0 and self.gas>=21000 and self.max_fee>=self.priority_fee,'EVM_TX','Invalid gas or chain ID')
        require(len(self.to) in (0,20) and len(self.data)<=131072,'EVM_TX','Invalid destination or data')
    @property
    def fields(self):return [self.chain_id,self.nonce,self.priority_fee,self.max_fee,self.gas,self.to,self.value,self.data,[]]
    @property
    def signing_hash(self):return keccak256(b'\x02'+rlp(self.fields))
    def sign(self,key,expected_sender):
        from .bitcoin import sign_digest
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
        require(address_from_key(key)==expected_sender,'SIGNER_SCOPE','Wrong EVM signer')
        # ECDSA can exceptionally have an x-coordinate >= group order; re-sign
        # rather than produce an Ethereum-unrepresentable recovery identifier.
        for _ in range(8):
            r,s=decode_dss_signature(sign_digest(key,self.signing_hash))
            for parity in (0,1):
                try:matches=recover_address(self.signing_hash,r,s,parity)==expected_sender
                except SwapError:matches=False
                if matches:return b'\x02'+rlp(self.fields+[parity,r,s])
        raise SwapError('EVM_SIGNATURE','Could not obtain an Ethereum signature')
    def validate_signed(self,raw,expected_sender):
        require(raw[:1]==b'\x02','EVM_TX','Only type-2 transactions supported')
        fields=decode_rlp(raw[1:])
        require(type(fields) is list and len(fields)==12,'EVM_TX','Wrong field count')
        require(rlp(fields[:9])==rlp(self.fields),'PLAN_MUTATED','Signed transaction changed approved fields')
        numbers=[]
        for value in fields[9:]:
            require(type(value) is bytes and len(value)<=32 and (not value or value[0]!=0),'EVM_SIGNATURE','Noncanonical signature integer')
            numbers.append(int.from_bytes(value,'big'))
        parity,r,s=numbers
        require(recover_address(self.signing_hash,r,s,parity)==expected_sender,'SIGNER_SCOPE','Unexpected recovered sender')
        return '0x'+keccak256(raw).hex()

class EVMAdapter:
    def __init__(self,rpc,genesis,chain_id,contract,runtime_hash,token_code_hashes=None):
        self.rpc=rpc;self.genesis=hex32(genesis);integer(chain_id,lo=1)
        self.chain_id=chain_id;address_bytes(contract);self.contract=contract
        self.runtime_hash=hex32(runtime_hash);self.token_code_hashes=token_code_hashes or {}
    def check_chain(self):
        require(int(self.rpc('eth_chainId'),16)==self.chain_id,'CHAIN_ID','Wrong EVM chain ID')
        require(self.rpc('eth_getBlockByNumber','0x0',False)['hash'][2:]==self.genesis,'GENESIS_MISMATCH','Wrong EVM genesis')
        require(self.rpc('eth_syncing') is False,'CHAIN_SYNC','EVM client still syncing')
        raw=bytes.fromhex(self.rpc('eth_getCode',self.contract,'latest')[2:])
        require(raw and keccak256(raw).hex()==self.runtime_hash,'CONTRACT_CODE','Unrecognized contract runtime')
    def observe(self,swap_id,expected,now):
        self.check_chain();hex32(swap_id)
        finalized=self.rpc('eth_getBlockByNumber','finalized',False)
        require(finalized and 'hash' in finalized,'FINALITY_UNAVAILABLE','Finalized tag required; no silent latest fallback')
        tag=finalized['number']
        call={'to':self.contract,'data':'0x'+calldata('getSwap(bytes32)',bytes.fromhex(swap_id)).hex()}
        code=bytes.fromhex(self.rpc('eth_getCode',self.contract,tag)[2:])
        require(keccak256(code).hex()==self.runtime_hash,'CONTRACT_CODE','Historical runtime differs')
        raw=bytes.fromhex(self.rpc('eth_call',call,tag)[2:])
        require(len(raw)==7*32,'CONTRACT_ABI','Unexpected HTLC view layout')
        words=[raw[i:i+32] for i in range(0,len(raw),32)]
        require(all(w[:12]==b'\x00'*12 for w in words[1:4]) and int.from_bytes(words[5],'big')<2**64,
                'CONTRACT_ABI','Noncanonical ABI address or timestamp')
        state=int.from_bytes(words[6],'big')
        require(state in (0,1,2,3),'CONTRACT_ABI','Unknown swap state')
        exact=(words[0].hex()==expected['hashlock'] and '0x'+words[1][-20:].hex()==expected['token']
               and '0x'+words[2][-20:].hex()==expected['refund_to'] and '0x'+words[3][-20:].hex()==expected['claim_to']
               and int.from_bytes(words[4],'big')==expected['amount'] and int.from_bytes(words[5],'big')==expected['refund_at'])
        # Read the block hash again: abort a snapshot assembled across a reorg.
        canonical=self.rpc('eth_getBlockByNumber',tag,False)['hash']==finalized['hash']
        return LegObservation(state!=0,exact,canonical,1,True,state==2,state==3,False,now)
    def funding_data(self,swap_id,hash_hex,claim_to,refund_at,*,token=None,amount=0):
        self.check_chain();hex32(swap_id);hex32(hash_hex);integer(refund_at,lo=500000000,hi=(1<<53)-1)
        if token is None:return calldata('lockNative(bytes32,bytes32,address,uint64)',bytes.fromhex(swap_id),bytes.fromhex(hash_hex),address_bytes(claim_to),refund_at)
        address_bytes(token)
        require(token in self.token_code_hashes,'TOKEN_DISABLED','Token has not passed the release allowlist')
        code=bytes.fromhex(self.rpc('eth_getCode',token,'latest')[2:])
        require(keccak256(code).hex()==self.token_code_hashes[token],'TOKEN_CODE','Token code changed')
        return calldata('lockToken(bytes32,bytes32,address,uint64,address,uint256)',bytes.fromhex(swap_id),bytes.fromhex(hash_hex),address_bytes(claim_to),refund_at,address_bytes(token),amount)
    def broadcast(self,raw):
        self.check_chain()
        require(type(raw) is bytes,'EVM_TX','Expected raw bytes')
        txid='0x'+keccak256(raw).hex()
        require(self.rpc('eth_sendRawTransaction','0x'+raw.hex())==txid,'TXID_MISMATCH','Unexpected EVM transaction hash')
        return txid


def lock_id(chain_id,contract,funder,salt):
    """Storage identifier returned by contract computeId; salt is agreement nonce."""
    integer(chain_id,lo=1);hex32(salt)
    return keccak256(abi_word(chain_id)+abi_word(address_bytes(contract))+abi_word(address_bytes(funder))+bytes.fromhex(salt)).hex()
