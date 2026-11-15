"""Application wire-path and recovery tests. Ledgers are deterministic test doubles."""
from dataclasses import asdict
from pathlib import Path
import json,os
import pytest
from swapnet.application import Application
from swapnet.authorization import Principal,PeerPrincipal
from swapnet.canonical import loads,dumps
from swapnet.errors import SwapError
from swapnet.journal import Journal
from swapnet.policy import Mandate,SafetyPolicy
from swapnet.recovery import export_bundle,restore_bundle
from swapnet.store import Store
from swapnet.vault import ForeignKeyVault,atomic_private_write
from test_execution_v2 import Identity,Ledger,Driver,Time,NETWORK,A,B,pair

@pytest.fixture
def apps(tmp_path):
    time=Time();ledgers={A:Ledger(A,time),B:Ledger(B,time)};nodes={};wire=[]
    for name in ('alice','bob'):
        folder=tmp_path/name;folder.mkdir(mode=0o700)
        store=Store(folder/'state.sqlite');vault=ForeignKeyVault(folder/'foreign-vault.json',b'1'*32)
        nodes[name]=Application(store,NETWORK,Identity(name),vault,{a:Driver(l,name) for a,l in ledgers.items()},
            lambda peer,command,raw,n=name:(wire.append((n,command,raw)) or True),clock=time,
            policy=SafetyPolicy(btx_confirmations=2,btc_confirmations=2,settlement_margin_seconds=10,reveal_margin_seconds=10))
    nodes['alice'].peer_connected(1);nodes['bob'].peer_connected(1)
    def deliver():
        n=0
        while wire:
            sender,command,raw=wire.pop(0);other='bob' if sender=='alice' else 'alice'
            nodes[other].on_message(1,command,raw);n+=1;assert n<256
    def step():
        deliver()
        for app in nodes.values():app.tick()
        deliver()
        for ledger in ledgers.values():ledger.mine()
        time.n+=1
    yield nodes,time,ledgers,wire,deliver,step
    for app in nodes.values():app.close()

def test_signed_wire_discovery_rfq_and_complete_swap(apps):
    nodes,time,ledgers,wire,deliver,step=apps
    mids={}
    for n,asset in [('alice',A),('bob',B)]:
        mandate=Mandate(n,asset,'10000000','100000','1000',time()+10000,'66'*32)
        mids[n]=nodes[n].rpc(Principal(n,True),'createswapmandate',{'mandate':asdict(mandate)})['mandate_id']
    market={'sell_asset':A,'buy_asset':B,'numerator':'2','denominator':'1','maker_fee_atoms':'10',
            'max_receive_network_fee_atoms':'100','max_input_atoms':'100000','expires_at':time()+10000}
    nodes['bob'].rpc(Principal('bob',True),'setswapmarket',{'market':market,'mandate_id':mids['bob'],
        'max_local_fee_atoms':'500','refund_fee_atoms':'100','claim_fee_atoms':'100'})
    deliver();assert nodes['alice'].rpc(Principal('alice'),'listswapproviders')['providers']
    rfq=nodes['alice'].rpc(Principal('alice'),'requestswapquote',{'sell_asset':A,'buy_asset':B,'sell_atoms':'10000'})
    for _ in range(4):step()
    quotes=nodes['alice'].rpc(Principal('alice'),'getswapquotes',{'request_id':rfq['request_id']})['quotes'];assert quotes
    sid=nodes['alice'].rpc(Principal('alice'),'acceptswapquote',{'quote_id':quotes[0]['id'],'mandate_id':mids['alice'],
        'max_local_fee_atoms':'500','refund_fee_atoms':'100'})['swap_id']
    for _ in range(40):step()
    for name,app in nodes.items():assert app.rpc(Principal(name),'getswap',{'swap_id':sid})['stage']=='complete'
    assert len(ledgers[A].records)==len(ledgers[B].records)==1

def test_peer_payload_cannot_create_native_principal(apps):
    nodes,*_=apps
    with pytest.raises(SwapError,match='AUTH'):nodes['alice'].rpc(PeerPrincipal('alice'),'withdrawswapprovider',{})
    with pytest.raises(SwapError,match='OWNER_REQUIRED'):nodes['alice'].rpc(Principal('agent'),'withdrawswapprovider',{'owner':True})

def test_wire_signature_tampering_is_rejected(apps):
    nodes,time,ledgers,wire,deliver,step=apps;deliver()
    nodes['alice'].rpc(Principal('alice'),'requestswapquote',{'sell_asset':A,'buy_asset':B,'sell_atoms':'10000'})
    nodes['alice'].tick();sender,command,raw=next(x for x in wire if x[1]=='swrfq')
    envelope=loads(raw);envelope['packet']['body']['payload']['rfq']['sell_atoms']='99999'
    with pytest.raises(SwapError,match='BAD_SIGNATURE'):nodes['bob'].on_message(1,command,dumps(envelope))
    assert not ledgers[A].records and not ledgers[B].records

def recovery_source(path):
    path.mkdir(mode=0o700);store=Store(path/'state.sqlite');journal=Journal(store)
    atomic_private_write(path/'vault.key',b'K'*32)
    vault=ForeignKeyVault(path/'foreign-vault.json',b'K'*32);key=vault.create_key('btc','22'*32,'claim');vault.save()
    journal.set_setting('recovery_test','durable');return store,journal,vault,key

def test_encrypted_recovery_roundtrip(tmp_path):
    store,j,v,k=recovery_source(tmp_path/'source');password='independent offline recovery passphrase 123'
    result=export_bundle(j,tmp_path/'source',password,NETWORK);store.close()
    raw=Path(result['path']).read_bytes();assert b'vault.key' not in raw and b'durable' not in raw
    dest=tmp_path/'restore';assert restore_bundle(result['path'],dest,password,NETWORK)['restored']
    restored=Store(dest/'state.sqlite')
    try:assert Journal(restored).setting('recovery_test')=='durable'
    finally:restored.close()
    rv=ForeignKeyVault(dest/'foreign-vault.json',(dest/'vault.key').read_bytes())
    assert rv.public_key(k,family='btc',genesis='22'*32,role='claim')==v.public_key(k,family='btc',genesis='22'*32,role='claim')

def test_recovery_wrong_password_network_and_nonempty_refused(tmp_path):
    store,j,_,_=recovery_source(tmp_path/'source');password='correct password long enough 12345'
    result=export_bundle(j,tmp_path/'source',password,NETWORK);store.close()
    with pytest.raises(SwapError,match='BACKUP_AUTHENTICATION'):restore_bundle(result['path'],tmp_path/'bad','wrong password long enough 12345',NETWORK)
    assert not (tmp_path/'bad').exists()
    with pytest.raises(SwapError,match='GENESIS_MISMATCH'):restore_bundle(result['path'],tmp_path/'bad',password,'33'*32)
    target=tmp_path/'nonempty';target.mkdir();(target/'keep').write_text('do not overwrite')
    with pytest.raises(SwapError,match='RESTORE_NONEMPTY'):restore_bundle(result['path'],target,password,NETWORK)
    assert (target/'keep').read_text()=='do not overwrite'

def test_revoked_mandate_blocks_new_funding(pair):
    pair.start();pair.deliver();journal=pair.nodes['alice'][1]
    s=journal.load(pair.sid)[1]
    with journal.store.lock:mid=journal.store.db.execute('SELECT mandate_id FROM reservations WHERE id=?',(s['reservation_id'],)).fetchone()[0]
    pair.nodes['alice'][2].revoke(Principal('alice',True),mid)
    for _ in range(4):pair.nodes['alice'][3].tick()
    assert not pair.a.records

def test_fee_bump_refund_preserves_scope_and_cap(pair):
    from swapnet.fee_bump import bump
    pair.start();pair.deliver();c=pair.nodes['alice'][3];c.tick();c.tick();pair.a.mine(3)
    pair.a.height=pair.state('alice')['agreement']['long_leg']['lock_value']
    with pytest.raises(SwapError,match='FEE_CAP'):bump(c,Principal('alice'),pair.sid,'refund','101')
    result=bump(c,Principal('alice'),pair.sid,'refund','20')
    assert result['beneficiary_changed'] is False and result['fee_atoms']=='20'
    ops=pair.nodes['alice'][1].operations(pair.sid)
    assert len([o for o in ops if o['kind']=='fund'])==1
    assert len([o for o in ops if o['kind']=='refund'])==2

def test_fee_bump_early_and_cross_principal_refused(pair):
    from swapnet.fee_bump import bump
    pair.start();pair.step();pair.step();c=pair.nodes['alice'][3]
    with pytest.raises(SwapError,match='FORBIDDEN'):bump(c,Principal('other'),pair.sid,'refund','20')
    with pytest.raises(SwapError,match='REFUND_EARLY'):bump(c,Principal('alice'),pair.sid,'refund','20')
    with pytest.raises(SwapError,match='REPLACEMENT_KIND'):bump(c,Principal('alice'),pair.sid,'fund','20')

def test_future_financial_schema_is_not_silently_downgraded(tmp_path):
    folder=tmp_path/'future';folder.mkdir(mode=0o700);store=Store(folder/'state.sqlite')
    try:
        store.db.execute('PRAGMA user_version=999')
        with pytest.raises(SwapError,match='SCHEMA_VERSION'):Journal(store)
        assert store.db.execute('PRAGMA user_version').fetchone()[0]==999
    finally:store.close()
