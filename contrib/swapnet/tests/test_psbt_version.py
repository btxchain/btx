"""Bitcoin Core defaults to PSBT v2, whose decodepsbt result has no top-level tx."""
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
import pytest
from swapnet.adapters import BitcoinAdapter, create_funded_psbt
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
        if method=='help':return 'walletcreatefundedpsbt inputs outputs locktime options bip32derivs version psbt_version'
        if method=='walletcreatefundedpsbt':
            assert args[3]=={'lockUnspents':False,'replaceable':False,'include_unsafe':False,
                             'fee_rate':2,'minconf':6}
            assert args[5:]==(None,0)
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
        if method=='help':return 'walletcreatefundedpsbt inputs outputs locktime options bip32derivs version psbt_version'
        if method=='walletcreatefundedpsbt':
            assert args[3]=={'lockUnspents':False,'replaceable':False,'include_unsafe':False,
                             'fee_rate':2,'minconf':1}
            assert args[5:]==(None,0)
            return {'psbt':'cHNidA','fee':'0.00001000'}
        raise AssertionError(method)
    adapter=BitcoinAdapter(arpc,awallet,GENESIS,'bcrt')
    adapter.prepare_funding('bcrt1qexample',10000,2,100000,1)
    with pytest.raises(SwapError,match='PSBT_VERSION'):
        adapter.sign_funding('cHNidA',approved_plan=None,is_owned_change=lambda s:False)
    assert 'walletprocesspsbt' not in calls

@pytest.mark.parametrize('supports_version',[False,True])
def test_wallet_psbt_version_contract(supports_version):
    funded=[]
    def caller(method,*args):
        if method=='help':return 'walletcreatefundedpsbt inputs outputs'+(' psbt_version' if supports_version else '')
        assert method=='walletcreatefundedpsbt'
        funded.append(args)
        assert 'psbt_version' not in args[3]
        assert args[5:]==((None,0) if supports_version else ())
        return {'psbt':'cHNidA','fee':'0.00001000'}
    assert create_funded_psbt(caller,[],[],0,{'fee_rate':2},True,request_v0=True)['psbt']=='cHNidA'
    assert len(funded)==1

def test_other_funding_rejection_is_not_retried():
    funded=[]
    def caller(method,*args):
        if method=='help':return 'walletcreatefundedpsbt psbt_version'
        funded.append(args)
        raise SwapError('CHAIN_RPC','Insufficient funds')
    with pytest.raises(SwapError,match='Insufficient funds'):
        create_funded_psbt(caller,[],[],0,{},True,request_v0=True)
    assert len(funded)==1

def test_native_btx_does_not_probe_bitcoin_arguments():
    def caller(method,*args):
        assert method=='walletcreatefundedpsbt' and len(args)==5
        return {'psbt':'cHNidA'}
    create_funded_psbt(caller,[],[],0,{},True,request_v0=False)

@pytest.mark.parametrize('failure',['fee','decode','sign','store',None])
def test_preparation_reserves_only_valid_inputs_and_cleans_its_failures(failure):
    from types import SimpleNamespace
    coin={'txid':'aa'*32,'vout':0}
    old=('bb'*32,1)
    locked={old}
    decoded={'txid':'cc'*32,'vin':[coin],
             'vout':[{'value':'0.00010000','scriptPubKey':{'hex':'00'}}]}
    def rpc(method,*args):
        if method=='decodepsbt':return {} if failure=='decode' else {'tx':decoded}
        if method=='gettxout':return {'value':'0.00010100','confirmations':10}
        if method=='decoderawtransaction':return {'txid':decoded['txid']}
        raise AssertionError(method)
    def wallet(method,*args):
        if method=='help':return 'walletcreatefundedpsbt psbt_version'
        if method=='walletcreatefundedpsbt':
            assert args[3]['lockUnspents'] is False
            assert args[5:]==(None,0)
            return {'psbt':'cHNidA','fee':'0.00000100'}
        if method=='lockunspent':
            keys={(c['txid'],c['vout']) for c in args[1]}
            assert old not in keys
            if args[0]:locked.difference_update(keys)
            else:
                assert not keys & locked
                locked.update(keys)
            return True
        raise AssertionError(method)
    stored=[]
    def reserve(*args):
        if failure=='store':raise SwapError('TEST_STORE','reservation rejected')
        stored.extend(args[2])
    driver=UTXODriver(BTC,rpc,wallet,wallet,SimpleNamespace(store=SimpleNamespace(lock_coins=reserve)),None,network=NET)
    driver.watch_terms=lambda *a:{'address':'bcrt1qfixture'}
    driver.ready=lambda:True
    def sign(*args,**kwargs):
        if failure=='sign':raise SwapError('TEST_SIGN','signer refused')
        return 'aa'
    driver.adapter.sign_funding=sign
    args=('1'*64,SimpleNamespace(amount_atoms='10000',lock_commitment='00'),{},'2'*64,'50' if failure=='fee' else '500')
    if failure:
        expected={'fee':'FEE_CAP','decode':'PSBT_VERSION','sign':'TEST_SIGN','store':'TEST_STORE'}[failure]
        with pytest.raises(SwapError,match=expected):driver.prepare_funding(*args)
        assert locked=={old} and not stored
    else:
        result=driver.prepare_funding(*args)
        assert result.txid==decoded['txid']
        assert locked=={old,(coin['txid'],0)} and stored==[coin['txid']+':0']
