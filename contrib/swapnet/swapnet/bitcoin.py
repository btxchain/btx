"""Bitcoin-only P2WSH HTLCs, canonical wire encoding, BIP143 SIGHASH_ALL.
Never use these serializers or secp256k1 keys for a BTX transaction.
"""
from dataclasses import dataclass, field
import hashlib
import struct
from .canonical import hex32, integer, hashlock
from .errors import require, SwapError

MAX_MONEY=21_000_000*100_000_000
SECP_ORDER=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def sha256(x): return hashlib.sha256(x).digest()
def sha256d(x): return sha256(sha256(x))
def u32(n): return struct.pack('<I',integer(n,hi=0xffffffff))
def u64(n): return struct.pack('<Q',integer(n,hi=MAX_MONEY))

def compact(n):
    integer(n,hi=0xffffffff)
    if n<253: return bytes([n])
    if n<=0xffff: return b'\xfd'+struct.pack('<H',n)
    return b'\xfe'+u32(n)

def vector(raw): return compact(len(raw))+raw

class Reader:
    def __init__(self,raw): self.raw,self.pos=raw,0
    def take(self,n):
        require(0 <= n <= len(self.raw)-self.pos,'TX_TRUNCATED','Truncated transaction')
        result=self.raw[self.pos:self.pos+n]; self.pos+=n; return result
    def integer(self,n): return int.from_bytes(self.take(n),'little')
    def compact(self):
        n=self.integer(1)
        if n<253:return n
        size={253:2,254:4,255:8}[n]; v=self.integer(size)
        require(v >= {253:253,254:65536,255:4294967296}[n] and v<=1000000,'VARINT','Noncanonical or excessive compact size')
        return v
    def vector(self): return self.take(self.compact())

def push(raw):
    require(len(raw)<=75,'SCRIPT_SIZE','Non-small script push')
    return bytes([len(raw)])+raw

def scriptnum(n):
    integer(n,lo=1,hi=499999999)
    if n<=16:return bytes([0x50+n])
    out=n.to_bytes((n.bit_length()+7)//8,'little')
    if out[-1]&0x80:out+=b'\x00'
    return push(out)

def validate_pubkey(key):
    require(type(key) is bytes and len(key)==33 and key[0] in (2,3),'BTC_KEY','Compressed secp256k1 pubkey required')
    from cryptography.hazmat.primitives.asymmetric import ec
    try: ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(),key)
    except ValueError as e: raise SwapError('BTC_KEY','Invalid curve point') from e

def htlc_script(hash_hex,claim_pub,refund_pub,refund_height):
    hex32(hash_hex); validate_pubkey(claim_pub); validate_pubkey(refund_pub)
    require(claim_pub != refund_pub,'KEY_REUSE','Claim/refund keys must differ')
    # IF SIZE 32 EQUALVERIFY SHA256 H EQUALVERIFY claimant CHECKSIG
    # ELSE height CLTV DROP refund_key CHECKSIG ENDIF
    return (b'\x63\x82\x01\x20\x88\xa8'+push(bytes.fromhex(hash_hex))+b'\x88'+push(claim_pub)+
            b'\xac\x67'+scriptnum(refund_height)+b'\xb1\x75'+push(refund_pub)+b'\xac\x68')

def p2wsh(script): return b'\x00\x20'+sha256(script)

def _polymod(values):
    chk=1; gen=[0x3b6a57b2,0x26508e6d,0x1ea119fa,0x3d4233dd,0x2a1462b3]
    for v in values:
        top=chk>>25; chk=((chk&0x1ffffff)<<5)^v
        for i in range(5):
            if (top>>i)&1:chk^=gen[i]
    return chk

def p2wsh_address(script,hrp):
    require(hrp in {'bc','tb','bcrt'},'BTC_NETWORK','Unknown Bitcoin address network')
    acc=bits=0; data=[0]
    for b in sha256(script):
        acc=((acc<<8)|b)&0xffff; bits+=8
        while bits>=5:bits-=5;data.append((acc>>bits)&31)
    if bits:data.append((acc<<(5-bits))&31)
    expanded=[ord(c)>>5 for c in hrp]+[0]+[ord(c)&31 for c in hrp]
    mod=_polymod(expanded+data+[0]*6)^1
    checksum=[(mod>>(5*(5-i)))&31 for i in range(6)]
    alphabet='qpzry9x8gf2tvdw0s3jn54khce6mua7l'
    return hrp+'1'+''.join(alphabet[x] for x in data+checksum)

@dataclass
class TxInput:
    txid: str
    vout: int
    sequence: int=0xfffffffd
    script_sig: bytes=b''
    witness: list=field(default_factory=list)
    def outpoint(self): return bytes.fromhex(hex32(self.txid))[::-1]+u32(self.vout)
    def encode(self): return self.outpoint()+vector(self.script_sig)+u32(self.sequence)

@dataclass
class TxOutput:
    atoms: int
    script: bytes
    def encode(self): return u64(self.atoms)+vector(self.script)

@dataclass
class Transaction:
    inputs:list
    outputs:list
    locktime:int=0
    version:int=2
    def encode(self,witness=True):
        require(0<len(self.inputs)<=256 and 0<len(self.outputs)<=256,'TX_COUNTS','Invalid input/output count')
        has_witness=witness and any(i.witness for i in self.inputs)
        raw=u32(self.version)+(b'\x00\x01' if has_witness else b'')
        raw+=compact(len(self.inputs))+b''.join(i.encode() for i in self.inputs)
        raw+=compact(len(self.outputs))+b''.join(o.encode() for o in self.outputs)
        if has_witness:
            for i in self.inputs: raw+=compact(len(i.witness))+b''.join(vector(w) for w in i.witness)
        return raw+u32(self.locktime)
    @property
    def txid(self):return sha256d(self.encode(False))[::-1].hex()
    def sighash_all(self,index,script,amount):
        require(type(index) is int and 0<=index<len(self.inputs),'INPUT_INDEX','Invalid input')
        i=self.inputs[index]
        data=(u32(self.version)+sha256d(b''.join(x.outpoint() for x in self.inputs))+
              sha256d(b''.join(u32(x.sequence) for x in self.inputs))+i.outpoint()+vector(script)+
              u64(amount)+u32(i.sequence)+sha256d(b''.join(o.encode() for o in self.outputs))+u32(self.locktime)+u32(1))
        return sha256d(data)
    @classmethod
    def decode(cls,raw):
        require(type(raw) is bytes and len(raw)<=1_000_000,'TX_SIZE','Invalid transaction size')
        r=Reader(raw); version=r.integer(4); n=r.compact(); witnessed=False
        if n==0:
            require(r.integer(1)==1,'TX_FLAGS','Unknown witness flags'); witnessed=True;n=r.compact()
        require(0<n<=256,'TX_COUNTS','Invalid input count')
        inputs=[]
        for _ in range(n):
            txid=r.take(32)[::-1].hex();vout=r.integer(4);sig=r.vector();sequence=r.integer(4)
            inputs.append(TxInput(txid,vout,sequence,sig))
        n=r.compact(); require(0<n<=256,'TX_COUNTS','Invalid output count')
        outputs=[]
        for _ in range(n):
            amount=r.integer(8);require(amount<=MAX_MONEY,'BTC_MONEY','Output exceeds Bitcoin money range')
            outputs.append(TxOutput(amount,r.vector()))
        require(sum(o.atoms for o in outputs)<=MAX_MONEY,'BTC_MONEY','Output total exceeds money range')
        if witnessed:
            for i in inputs:
                count=r.compact();require(count<=100,'TX_WITNESS','Witness item limit exceeded')
                i.witness=[r.vector() for _ in range(count)]
            require(any(i.witness for i in inputs),'TX_WITNESS','Superfluous witness encoding')
        result=cls(inputs,outputs,r.integer(4),version)
        require(r.pos==len(raw),'TX_TRAILING','Trailing transaction bytes')
        return result

def sign_digest(private_key,digest32):
    from cryptography.hazmat.primitives.asymmetric import ec,utils
    from cryptography.hazmat.primitives import hashes
    require(len(digest32)==32,'DIGEST','Expected 32-byte signing digest')
    signature=private_key.sign(digest32,ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    r,s=utils.decode_dss_signature(signature)
    return utils.encode_dss_signature(r,min(s,SECP_ORDER-s))

def build_spend(txid,vout,amount,fee,destination_script,script,private_key,*,secret=None,refund_height=None,
                expected_pubkey=None):
    """Sign one verified HTLC input. The caller independently verifies the funding script.
    BTC value, destination, fee cap and branch must already match an owner-approved plan.
    """
    from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
    pub=private_key.public_key().public_bytes(Encoding.X962,PublicFormat.CompressedPoint)
    require(expected_pubkey is not None and pub==expected_pubkey,'SIGNER_SCOPE','Unexpected BTC signing key')
    require(type(amount) is int and type(fee) is int and 0<fee<amount<=MAX_MONEY,'FEE','Invalid value or fee')
    require(amount-fee>=1000 and 0<len(destination_script)<=10000,'DUST','Invalid or uneconomic output')
    require((secret is None) != (refund_height is None),'SPEND_BRANCH','Choose exactly one branch')
    claim=secret is not None
    parsed=parse_htlc_script(script)
    if claim:
        require(hashlock(secret)==parsed['hashlock'],'PREIMAGE','Secret does not match the funded script')
        require(pub==parsed['claim_pub'],'SIGNER_SCOPE','Wrong claim key')
    else:
        integer(refund_height,lo=1,hi=499999999)
        require(refund_height==parsed['refund_height'] and pub==parsed['refund_pub'],'SIGNER_SCOPE','Wrong refund key or height')
    tx=Transaction([TxInput(txid,vout)],[TxOutput(amount-fee,destination_script)],0 if claim else refund_height)
    sig=sign_digest(private_key,tx.sighash_all(0,script,amount))+b'\x01'
    tx.inputs[0].witness=[sig,secret,b'\x01',script] if claim else [sig,b'',script]
    return tx


def parse_htlc_script(script):
    """Exact template parser: reject alternate branches, nonminimal height and tails."""
    require(type(script) is bytes and 110<=len(script)<=160,'SCRIPT_SHAPE','Wrong HTLC script size')
    r=Reader(script)
    require(r.take(7)==b'\x63\x82\x01\x20\x88\xa8\x20','SCRIPT_SHAPE','Wrong claim prefix')
    h=r.take(32).hex()
    require(r.take(2)==b'\x88\x21','SCRIPT_SHAPE','Wrong hash/key push')
    claim=r.take(33)
    require(r.take(2)==b'\xac\x67','SCRIPT_SHAPE','Wrong branch delimiter')
    op=r.integer(1)
    if 0x51<=op<=0x60:height=op-0x50
    else:
        require(1<=op<=5,'SCRIPT_SHAPE','Wrong height encoding')
        raw=r.take(op)
        require(not raw[-1]&0x80,'SCRIPT_SHAPE','Negative height')
        height=int.from_bytes(raw,'little')
    require(r.take(3)==b'\xb1\x75\x21','SCRIPT_SHAPE','Wrong refund prefix')
    refund=r.take(33)
    require(r.take(2)==b'\xac\x68' and r.pos==len(script),'SCRIPT_SHAPE','Extra spending path or trailing bytes')
    require(htlc_script(h,claim,refund,height)==script,'SCRIPT_SHAPE','Noncanonical HTLC')
    return {'hashlock':h,'claim_pub':claim,'refund_pub':refund,'refund_height':height}
