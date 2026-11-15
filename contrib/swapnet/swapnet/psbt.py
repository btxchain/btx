"""Bounded BIP174 map editing, with no BTX transaction deserialization.

The native node creates/decodes the unsigned transaction; this module adds only
standard witness-UTXO and SHA256-preimage records. PQ keys never enter Python.
"""
import base64
import struct
from .bitcoin import Reader,compact,vector
from .errors import require,SwapError

MAX_PSBT=4_000_000

def maps(encoded):
    require(type(encoded) is str and len(encoded)<=MAX_PSBT,'PSBT_SIZE','PSBT too large')
    try:raw=base64.b64decode(encoded,validate=True)
    except Exception as e:raise SwapError('PSBT_ENCODING','Invalid PSBT base64') from e
    r=Reader(raw);require(r.take(5)==b'psbt\xff','PSBT_MAGIC','Invalid PSBT header')
    out=[]
    while r.pos<len(raw):
        m={}
        while True:
            key=r.vector()
            if not key:break
            require(key not in m,'PSBT_DUPLICATE','Duplicate PSBT map key')
            m[key]=r.vector();require(len(m)<=1024,'PSBT_LIMIT','Too many PSBT fields')
        out.append(m);require(len(out)<=513,'PSBT_LIMIT','Too many PSBT maps')
    require(len(out)>=3 and b'\x00' in out[0],'PSBT_VERSION','Expected PSBT v0 unsigned transaction')
    return out

def encode(items):
    raw=b'psbt\xff'+b''.join(b''.join(vector(k)+vector(v) for k,v in sorted(m.items()))+b'\0' for m in items)
    require(len(raw)<=MAX_PSBT,'PSBT_SIZE','PSBT too large')
    return base64.b64encode(raw).decode()

def add_witness_utxo(encoded,amount,script,input_index=0):
    require(type(amount) is int and 0<amount<1<<63,'PSBT_AMOUNT','Invalid funding amount')
    ms=maps(encoded);require(0<=input_index<len(ms)-2,'PSBT_INPUT','Invalid input index')
    value=struct.pack('<q',amount)+vector(bytes.fromhex(script));m=ms[1+input_index]
    require(b'\x01' not in m or m[b'\x01']==value,'PSBT_UTXO','Conflicting witness UTXO')
    m[b'\x01']=value;return encode(ms)
