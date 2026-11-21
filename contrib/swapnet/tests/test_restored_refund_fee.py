"""Actual coordinator/SQLite; deterministic chain RPC and signing, no native chain."""
from copy import deepcopy
from decimal import Decimal
from types import SimpleNamespace
import pytest
from test_execution_v2 import pair,A,NETWORK
from test_restored_history import setup,TXID
from swapnet.assets import Asset
from swapnet.authorization import Principal
from swapnet.errors import SwapError,RPCTransportTimeout
from swapnet.fee_bump import bump
from swapnet.terms import Agreement

BLOCK='bc'*32
MISSING=object()

def ready(pair,*,adopted=False,fee=Decimal('0.00000030')):
    c,d,h=setup(pair,'unique');h.add(TXID,0)
    c.tick_one(pair.sid);c.tick_one(pair.sid)
    # Restore scan fixture uses a BTC wrapper over a BTX leg. Once adopted,
    # restore its actual asset identity for production fee binding/check_chain.
    d.asset=Asset.parse(A)
    state=pair.state('alice');leg=state['agreement']['long_leg']
    pair.a.records[TXID]={'terms':leg,'state':'locked','confirmations':3,'preimage':None}
    pair.a.height=leg['lock_value']
    calls=[];settings={'fee':fee,'fail':None,'hint':False,'mutate':None}
    pair.fee_preparations=0
    prepare=d.prepare_refund
    def prepare_refund(*args,**kwargs):
        pair.fee_preparations+=1
        return prepare(*args,**kwargs)
    d.prepare_refund=prepare_refund
    oldrpc=d.rpc
    def rpc(method,*args):
        calls.append((method,args))
        if method=='getblockhash':return NETWORK
        if method=='getblockchaininfo':return {'initialblockdownload':False}
        if method=='getblockheader':return {'confirmations':3}
        if method=='getrawtransaction':
            if settings['fail']:raise settings['fail']
            out={'txid':TXID,'blockhash':BLOCK,'confirmations':3,'vout':[{'n':0,'value':Decimal(leg['amount_atoms'])/100000000,'scriptPubKey':{'hex':leg['lock_commitment']}}]}
            if settings['fee'] is not MISSING and (not settings['hint'] or len(args)==3):out['fee']=settings['fee']
            if settings['mutate']:settings['mutate'](out)
            return out
        return oldrpc(method,*args)
    def wallet(method,*args):
        if method=='gettransaction' and args[0]==TXID and settings['hint']:return {'txid':TXID,'blockhash':BLOCK,'fee':Decimal('-999')}
        raise SwapError('CHAIN_RPC','fixture history unavailable')
    d.rpc=d.adapter.rpc=rpc;d.wallet=d.watch=wallet
    if adopted:
        j=pair.nodes['alice'][1];rev,state=j.load(pair.sid)
        state['fund_op']=j.prepare(pair.sid,A,'fund',TXID,'ee',{'reference':state['refs']['a'],'fee_atoms':'0','adopted_output':True})
        j.save(pair.sid,state,rev)
    return c,d,settings,calls

def snapshot(pair):
    st,j,_,_=pair.nodes['alice']
    return deepcopy({'session':j.load(pair.sid),'ops':j.operations(pair.sid,private=True),
        'budget':st.db.execute('SELECT held,used FROM mandates').fetchall(),
        'grants':st.db.execute('SELECT * FROM sn_grants').fetchall(),
        'transactions':pair.a.transactions,'records':pair.a.records,'preparations':pair.fee_preparations})

def replace(pair,c):return bump(c,Principal('alice'),pair.sid,'refund','20')

def reopen(pair,d):
    pair.restart('alice');c=pair.nodes['alice'][3];c.drivers[A]=d;return c

@pytest.mark.parametrize('adopted',[False,True])
def test_original_fee_recovery_and_restart(pair,adopted):
    c,d,settings,calls=ready(pair,adopted=adopted)
    before=snapshot(pair);c=reopen(pair,d);assert snapshot(pair)==before
    out=replace(pair,c);after=snapshot(pair)
    assert out['fee_atoms']=='20' and out['beneficiary_changed'] is False
    assert after['session'][1]['refs']==before['session'][1]['refs']
    assert d.funding_calls==0 and after['budget']==before['budget'] and after['grants']==before['grants']
    assert after['preparations']==1 and before['preparations']==0
    assert len(after['ops'])==len(before['ops'])+1
    assert after['ops'][:-1]==before['ops']
    assert len(after['transactions'])==len(before['transactions'])+1
    assert ('getrawtransaction',(TXID,2)) in calls
    c=reopen(pair,d);assert snapshot(pair)==after

@pytest.mark.parametrize('fee,code',[(MISSING,'FUNDING_FEE_UNKNOWN'),(None,'FUNDING_FEE_UNKNOWN'),
    ('-0.00000001','RPC_AMOUNT'),('0.000000001','RPC_AMOUNT'),('NaN','RPC_AMOUNT'),('Infinity','RPC_AMOUNT'),
    ('wat','RPC_AMOUNT'),(0.0000003,'RPC_AMOUNT'),(True,'RPC_AMOUNT'),('1e100','RPC_AMOUNT'),('1e999999999','RPC_AMOUNT'),('0.00000030'+'0'*110+'1','RPC_AMOUNT')])
def test_unknown_or_invalid_fee_refuses_without_effects(pair,fee,code):
    c,d,settings,calls=ready(pair,fee=fee);before=snapshot(pair)
    for reopen_first in (False,True):
        if reopen_first:c=reopen(pair,d)
        with pytest.raises(SwapError) as error:replace(pair,c)
        assert error.value.code==code
        assert snapshot(pair)==before and d.funding_calls==0
    settings['fee']=Decimal('0.00000030')
    assert replace(pair,c)['fee_atoms']=='20' and d.funding_calls==0
    after=snapshot(pair);reopen(pair,d);assert snapshot(pair)==after

@pytest.mark.parametrize('fee,ok',[(0,True),(480,True),(481,False)])
def test_combined_cap_and_measured_zero(pair,fee,ok):
    c,d,settings,calls=ready(pair,adopted=True,fee=Decimal(fee)/100000000);before=snapshot(pair)
    if ok:assert replace(pair,c)['fee_atoms']=='20'
    else:
        with pytest.raises(SwapError,match='FEE_CAP'):replace(pair,c)
        assert snapshot(pair)==before
    assert d.funding_calls==0

@pytest.mark.parametrize('change', ['txid','script','amount','vout','raw'])
def test_wrong_original_refuses(pair,change):
    c,d,settings,calls=ready(pair);before=snapshot(pair)
    def mutate(tx):
        if change=='txid':tx['txid']='cd'*32
        if change=='script':tx['vout'][0]['scriptPubKey']['hex']='ff'
        if change=='amount':tx['vout'][0]['value']+=Decimal('0.00000001')
        if change=='vout':tx['vout'][0]['n']=1
        if change=='raw':tx['hex']='ff'
    settings['mutate']=mutate
    if change=='raw':
        old=d.rpc
        def rpc(m,*a):return {'txid':'cd'*32} if m=='decoderawtransaction' else old(m,*a)
        d.rpc=rpc
    with pytest.raises(SwapError,match='RECOVERY_CONFLICT'):replace(pair,c)
    assert snapshot(pair)==before and d.funding_calls==0

def test_transport_failure_then_retry(pair):
    c,d,settings,calls=ready(pair);before=snapshot(pair);settings['fail']=RPCTransportTimeout()
    with pytest.raises(RPCTransportTimeout):replace(pair,c)
    assert snapshot(pair)==before
    c=reopen(pair,d);settings['fail']=None
    assert replace(pair,c)['fee_atoms']=='20' and d.funding_calls==0

def test_explicit_block_hint_not_wallet_fee(pair):
    c,d,settings,calls=ready(pair);settings['hint']=True
    assert replace(pair,c)['fee_atoms']=='20'
    assert [a for m,a in calls if m=='getrawtransaction' and a[0]==TXID]==[(TXID,2),(TXID,2,BLOCK)]

def test_cap_principal_maturity_still_refuse_before_fee_lookup(pair):
    c,d,settings,calls=ready(pair);before=snapshot(pair)
    for principal,fee,height,code in [('alice','101',pair.a.height,'FEE_CAP'),('other','20',pair.a.height,'FORBIDDEN'),('alice','20',pair.a.height-1,'REFUND_EARLY')]:
        pair.a.height=height
        with pytest.raises(SwapError,match=code):bump(c,Principal(principal),pair.sid,'refund',fee)
        assert snapshot(pair)==before
    assert not calls

@pytest.mark.parametrize('family',['btc','btx'])
def test_fee_lookup_binds_chain_and_asset(pair,family):
    from dataclasses import replace as change
    from swapnet.drivers import UTXODriver
    c,d,settings,calls=ready(pair)
    asset=family+':'+NETWORK+':0:native'
    driver=UTXODriver(asset,d.rpc,d.wallet,d.watch,None,None,network=NETWORK)
    leg=change(Agreement.parse(pair.state('alice')['agreement']).long_leg,asset=asset)
    assert driver.historical_funding_fee(leg,{'txid':TXID,'vout':0})=='30'
    with pytest.raises(SwapError,match='CHAIN'):driver.historical_funding_fee(change(leg,asset='btc:'+('44'*32)+':0:native'),{'txid':TXID,'vout':0})
    old=driver.rpc
    def wrong(m,*a):return '44'*32 if m=='getblockhash' else old(m,*a)
    driver.adapter.rpc=wrong
    with pytest.raises(SwapError,match='GENESIS_MISMATCH'):driver.historical_funding_fee(leg,{'txid':TXID,'vout':0})

@pytest.mark.parametrize('unsupported',[False,True])
def test_unavailable_node_fee_preserves_original_and_retries(pair,unsupported):
    c,d,settings,calls=ready(pair,fee=MISSING);before=snapshot(pair)
    if unsupported:settings['fail']=SwapError('CHAIN_RPC','unsupported verbosity')
    with pytest.raises(SwapError,match='FUNDING_FEE_UNKNOWN'):replace(pair,c)
    assert snapshot(pair)==before
    settings['fail']=None;settings['fee']=Decimal('0.00000030');c=reopen(pair,d)
    assert replace(pair,c)['fee_atoms']=='20' and d.funding_calls==0

@pytest.mark.parametrize('conflict',['transaction','block'])
def test_noncanonical_original_refuses(pair,conflict):
    c,d,settings,calls=ready(pair);before=snapshot(pair)
    if conflict=='transaction':settings['mutate']=lambda tx:tx.update(confirmations=-1)
    else:
        old=d.rpc
        def rpc(m,*a):return {'confirmations':-1} if m=='getblockheader' else old(m,*a)
        d.rpc=rpc
    with pytest.raises(SwapError,match='CHAIN_CONFLICT'):replace(pair,c)
    assert snapshot(pair)==before and d.funding_calls==0

@pytest.mark.parametrize('malformed',['fractional_output','invalid_output','nonobject_decode'])
def test_malformed_original_amount_or_decode_refuses(pair,malformed):
    c,d,settings,calls=ready(pair);before=snapshot(pair)
    def mutate(tx):
        if malformed=='fractional_output':tx['vout'][0]['value']='0.00010000'+'0'*100+'1'
        elif malformed=='invalid_output':tx['vout'][0]['value']='bad'
        else:tx['hex']='ee'
    settings['mutate']=mutate
    if malformed=='nonobject_decode':
        old=d.rpc
        def rpc(m,*a):return [] if m=='decoderawtransaction' else old(m,*a)
        d.rpc=rpc
    with pytest.raises(SwapError,match='RECOVERY_CONFLICT' if malformed=='nonobject_decode' else 'RPC_AMOUNT'):replace(pair,c)
    assert snapshot(pair)==before
