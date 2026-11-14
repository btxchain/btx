from cryptography.hazmat.primitives.asymmetric import ec,utils
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
import pytest
from swapnet.bitcoin import *
from swapnet.errors import SwapError
KEY1=ec.derive_private_key(1,ec.SECP256K1());KEY2=ec.derive_private_key(2,ec.SECP256K1())
PUB1=KEY1.public_key().public_bytes(Encoding.X962,PublicFormat.CompressedPoint)
PUB2=KEY2.public_key().public_bytes(Encoding.X962,PublicFormat.CompressedPoint)
SECRET=bytes.fromhex('42'*32)
def script(height=500):return htlc_script(hashlock(SECRET),PUB1,PUB2,height)
@pytest.mark.parametrize('height',[1,16,17,127,128,255,32768,499999999])
def test_htlc_exact_roundtrip(height):
    s=script(height);assert parse_htlc_script(s)['refund_height']==height
    with pytest.raises(SwapError):parse_htlc_script(s+b'\x51')
def test_claim_signature_binds_destination():
    s=script();tx=build_spend('a'*64,0,100000,1000,b'\x00\x14'+b'\x11'*20,s,KEY1,secret=SECRET,expected_pubkey=PUB1)
    sig=tx.inputs[0].witness[0][:-1];d=tx.sighash_all(0,s,100000)
    KEY1.public_key().verify(sig,d,ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    tx.outputs[0].script=b'\x00\x14'+b'\x22'*20
    with pytest.raises(Exception):KEY1.public_key().verify(sig,tx.sighash_all(0,s,100000),ec.ECDSA(utils.Prehashed(hashes.SHA256())))
def test_refund_script_and_roundtrip():
    s=script();tx=build_spend('a'*64,1,100000,1000,b'\x00\x14'+b'\x11'*20,s,KEY2,refund_height=500,expected_pubkey=PUB2)
    assert tx.locktime==500 and tx.inputs[0].witness[1]==b''
    assert Transaction.decode(tx.encode()).encode()==tx.encode()
    assert Transaction.decode(tx.encode()).txid==tx.txid
@pytest.mark.parametrize('kwargs',[{'secret':b'x'*32,'expected_pubkey':PUB1},{'secret':SECRET,'expected_pubkey':PUB2},{'refund_height':501,'expected_pubkey':PUB1}])
def test_wrong_branch_key_secret(kwargs):
    with pytest.raises(SwapError):build_spend('a'*64,0,100000,1000,b'\x51',script(),KEY1,**kwargs)
def test_same_keys_rejected():
    with pytest.raises(SwapError):htlc_script(hashlock(SECRET),PUB1,PUB1,500)
def test_bech32_checksum():
    address=p2wsh_address(script(),'bcrt');hrp,data=address.rsplit('1',1)
    values=['qpzry9x8gf2tvdw0s3jn54khce6mua7l'.index(c) for c in data]
    from swapnet.bitcoin import _polymod
    assert _polymod([ord(c)>>5 for c in hrp]+[0]+[ord(c)&31 for c in hrp]+values)==1
@pytest.mark.parametrize('raw',[b'',b'\xfd\xfc\x00',b'\xfe\xff\xff\x00\x00'])
def test_noncanonical_varint(raw):
    with pytest.raises(SwapError):Reader(raw).compact()
