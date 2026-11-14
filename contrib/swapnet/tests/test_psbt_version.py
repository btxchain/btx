"""Bitcoin Core defaults to PSBT v2, whose decodepsbt result has no top-level tx."""
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
import pytest
from swapnet.adapters import BitcoinAdapter
from swapnet.bitcoin import htlc_script,p2wsh
from swapnet.canonical import hashlock
from swapnet.drivers import UTXODriver
from swapnet.errors import SwapError
from swapnet.terms import LegTerms
from conftest import NET,BTC

GENESIS='b'*64
SECRET=bytes.fromhex('11'*32)

def test_funding_requests_psbt_v0_and_stops_when_tx_missing():
    k1=ec.derive_private_key(1,ec.SECP256K1());k2=ec.derive_private_key(2,ec.SECP256K1())
    p1=k1.public_key().public_bytes(Encoding.X962,PublicFormat.CompressedPoint)
    p2=k2.public_key().public_bytes(Encoding.X962,PublicFormat.CompressedPoint)
    spk=p2wsh(htlc_script(hashlock(SECRET),p1,p2,500)).hex()
    terms=LegTerms(BTC,'10000',hashlock(SECRET),p1.hex(),p2.hex(),'bc1payout','bc1refund','height',500,spk,'50','50')
    calls=[]
    def rpc(method,*args):
        calls.append(method)
        if method=='validateaddress':return {'isvalid':True}
        if method=='getdescriptorinfo':return {'checksum':'abcd1234'}
        if method=='getblockhash':return GENESIS
        if method=='getblockchaininfo':return {'initialblockdownload':False}
        if method=='decodepsbt':return {}
        raise AssertionError(method)
    def wallet(method,*args):
        calls.append(method)
        if method=='getwalletinfo':return {}
        if method=='walletcreatefundedpsbt':
            assert args[3]=={'lockUnspents':True,'replaceable':False,'include_unsafe':False,
                             'fee_rate':2,'minconf':6,'psbt_version':0}
            return {'psbt':'cHNidA','fee':'0.00001000'}
        raise AssertionError(method)
    def watch(method,*args):
        calls.append(method)
        assert method=='importdescriptors'
        return [{'success':True}]
    driver=UTXODriver(BTC,rpc,wallet,watch,None,None,network=NET,hrp='bcrt')
    with pytest.raises(SwapError,match='PSBT_VERSION'):
        driver.prepare_funding('1'*64,terms,{},'2'*64,'1000')
    assert 'gettxout' not in calls and 'walletprocesspsbt' not in calls
    calls.clear()
    def arpc(method,*args):
        calls.append(method)
        if method=='getblockhash':return GENESIS
        if method=='getblockchaininfo':return {'initialblockdownload':False}
        if method=='decodepsbt':return {'psbt_version':2}
        raise AssertionError(method)
    def awallet(method,*args):
        calls.append(method)
        if method=='walletcreatefundedpsbt':
            assert args[3]=={'lockUnspents':False,'replaceable':False,'include_unsafe':False,
                             'fee_rate':2,'minconf':1,'psbt_version':0}
            return {'psbt':'cHNidA','fee':'0.00001000'}
        raise AssertionError(method)
    adapter=BitcoinAdapter(arpc,awallet,GENESIS,'bcrt')
    adapter.prepare_funding('bcrt1qexample',10000,2,100000,1)
    with pytest.raises(SwapError,match='PSBT_VERSION'):
        adapter.sign_funding('cHNidA',approved_plan=None,is_owned_change=lambda s:False)
    assert 'walletprocesspsbt' not in calls
