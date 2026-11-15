import pytest
from swapnet.canonical import *
from swapnet.errors import SwapError
from swapnet.assets import Asset
from swapnet.adapters import to_atoms,coin_string
from decimal import Decimal

def test_canonical_order():assert dumps({'b':2,'a':'3'})==b'{"a":"3","b":2}'
@pytest.mark.parametrize('raw',[b'{"a":1,"a":2}',b'{"a":NaN}',b'{"a":1.2}',b'{"a":1e2}',b'{"a":"\xc3\xa9"}',b'{"a":9007199254740992}',b'{"Bad":1}',b'['*25+b'0'+b']'*25])
def test_reject_noncanonical_input(raw):
    with pytest.raises(SwapError):loads(raw)
@pytest.mark.parametrize('v',['01','+1','-1','1.0',' 1',True,1,1.0,str(2**256)])
def test_atoms_reject(v):
    with pytest.raises(SwapError):atoms(v)
def test_full_uint256():assert atoms(str(2**256-1))==2**256-1
@pytest.mark.parametrize('n',[0,1,2100000000000000,123456789])
def test_decimal_roundtrip(n):assert to_atoms(coin_string(n))==n
@pytest.mark.parametrize('v',[0.1,Decimal('0.000000001'),'-1'])
def test_amount_rejection(v):
    with pytest.raises(SwapError):to_atoms(v)
def test_asset_scope():
    a=Asset('evm','a'*64,1);assert Asset.parse(a.id)==a
    assert a.id!=Asset('evm','b'*64,1).id
    with pytest.raises(SwapError):Asset.parse('btc:'+('a'*64)+':00:native')
