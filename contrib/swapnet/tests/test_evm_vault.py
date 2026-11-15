from dataclasses import replace
from cryptography.hazmat.primitives.asymmetric import ec
import pytest
from swapnet.evm import *
from swapnet.vault import ForeignKeyVault
from swapnet.errors import SwapError

def test_keccak_known_vectors():
    assert keccak256(b'').hex()=='c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470'
    assert keccak256(b'abc').hex()=='4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45'
@pytest.mark.parametrize('value',[b'',b'cat',b'x'*80,[],[b'cat',b'dog'],[[],[b'a']]])
def test_rlp(value):assert decode_rlp(rlp(value))==value
@pytest.mark.parametrize('raw',[b'\x81\x00',b'\xb8\x01x',b'\xc1',b'\x80\x80'])
def test_bad_rlp(raw):
    with pytest.raises(SwapError):decode_rlp(raw)
def test_ethereum_key_one_known_address():
    assert address_from_key(ec.derive_private_key(1,ec.SECP256K1()))=='0x7e5f4552091a69125d5dfcb7b8c2659029395bdf'
def test_type2_signing_exact_plan():
    key=ec.derive_private_key(1,ec.SECP256K1());addr=address_from_key(key)
    tx=Eip1559Transaction(1,0,1000000000,2000000000,21000,bytes.fromhex('12'*20),100,b'')
    raw=tx.sign(key,addr);assert tx.validate_signed(raw,addr)=='0x'+keccak256(raw).hex()
    with pytest.raises(SwapError):replace(tx,value=101).validate_signed(raw,addr)
    with pytest.raises(SwapError):replace(tx,chain_id=2).validate_signed(raw,addr)
def test_vault_independence_and_encryption(tmp_path):
    path=tmp_path/'vault.json';v=ForeignKeyVault(path,b'test-only-strong-passphrase')
    a=v.create_key('btc','a'*64,'claim');b=v.create_key('evm','b'*64,'claim')
    assert v.entries[a]['scalar']!=v.entries[b]['scalar']
    assert v.entries[a]['scalar'].encode() not in path.read_bytes()
    w=ForeignKeyVault(path,b'test-only-strong-passphrase');assert w.public_key(a,family='btc',genesis='a'*64,role='claim')
    with pytest.raises(SwapError):w.key(a,family='evm',genesis='b'*64,role='claim')
    with pytest.raises(SwapError):w.create_key('btx','a'*64,'claim')
    with pytest.raises(SwapError):ForeignKeyVault(path,b'incorrect-test-passphrase')
