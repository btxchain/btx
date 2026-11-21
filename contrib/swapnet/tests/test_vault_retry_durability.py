"""Vault retry regressions: encrypted vault/SQLite real, chain/signing simulated."""
from copy import deepcopy
from pathlib import Path
import os
import pytest
from test_execution_v2 import pair,A,B,NETWORK
from swapnet.drivers import UTXODriver
from swapnet.vault import ForeignKeyVault
import swapnet.vault as vault_module
from swapnet.errors import SwapError

PASSWORD=b'0123456789abcdef0123456789abcdef'
OLD_SID='99'*32

def disk(v):return ForeignKeyVault(v.path,PASSWORD)
def seed(v):
    old_key=v.create_key('btc','22'*32,'refund');old_hash=v.new_secret(OLD_SID)
    return old_key,old_hash,deepcopy(v.entries)
def old_survives(v,old):
    restored=disk(v)
    assert all(restored.entries.get(k)==val for k,val in old.items())

def fault(monkeypatch,v):
    real=os.replace;state={'enabled':False,'hits':0,'old':None}
    def replace(src,dst):
        if Path(dst)==v.path and state['enabled']:
            state['hits']+=1;state['old']=v.path.read_bytes();raise OSError('injected vault replacement failure')
        return real(src,dst)
    monkeypatch.setattr(vault_module.os,'replace',replace)
    return state

def completed_until_claim(p):
    for _ in range(20):
        if p.state('alice').get('claim_op'):return
        p.deliver();p.nodes['alice'][3].tick_one(p.sid)
        if p.state('alice').get('claim_op'):return
        p.nodes['bob'][3].tick_one(p.sid);p.deliver();p.a.mine();p.b.mine();p.time.n+=1
    raise AssertionError('fixture did not reach original claim')

def test_healthy_observed_secret_survives_restart(pair):
    pair.start();pair.deliver();v=pair.nodes['bob'][3].vault;_,_,old=seed(v)
    completed_until_claim(pair)
    c=pair.nodes['bob'][3];c.tick_one(pair.sid)
    sid='secret_'+pair.sid;expected=deepcopy(v.entries[sid]);assert disk(v).entries[sid]==expected
    old_survives(v,old);pair.restart('bob')
    assert pair.nodes['bob'][3].vault.entries[sid]==expected

def test_failed_start_then_real_bitcoin_key_retry(pair,monkeypatch):
    c=pair.nodes['alice'][3];v=c.vault;_,_,old=seed(v)
    # Exercise the actual Bitcoin key-creation/save method. Other chain actions
    # continue to use Pair's deterministic drivers; this is not native RPC.
    native_key_driver=UTXODriver(B,None,lambda m,*a:'fixture-btc-payout',None,None,v,network=NETWORK)
    pair.nodes['alice'][3].drivers[B].new_key=native_key_driver.new_key
    state=fault(monkeypatch,v);real_start=c.start;captured={}
    def start(*args,**kwargs):
        captured.update(args=args,kwargs=kwargs)
        return real_start(*args,**kwargs)
    monkeypatch.setattr(c,'start',start)
    write=vault_module.atomic_private_write
    def fail_new_secret(path,raw):
        if Path(path)==v.path and any(k.startswith('secret_') and k not in old for k in v.entries):state['enabled']=True
        return write(path,raw)
    with monkeypatch.context() as scope:
        scope.setattr(vault_module,'atomic_private_write',fail_new_secret)
        with pytest.raises(OSError,match='injected vault'):pair.start()
    state['enabled']=False
    new_ids=[k for k in v.entries if k.startswith('secret_') and k not in old]
    assert len(new_ids)==1 and new_ids[0] not in disk(v).entries
    expected=deepcopy(v.entries[new_ids[0]])
    assert v.path.read_bytes()==state['old'] and state['hits']==1
    assert not list(v.path.parent.glob('.swapnet-*'));old_survives(v,old)
    outcome=real_start(*captured['args'],**captured['kwargs'])
    pair.sid=outcome['swap_id']
    assert new_ids[0]=='secret_'+pair.sid
    assert disk(v).entries[new_ids[0]]==expected
    old_survives(v,old);pair.restart('alice')
    assert pair.nodes['alice'][3].vault.entries[new_ids[0]]==expected
    assert not pair.a.records and not pair.b.records

@pytest.mark.parametrize('failures',[1,2])
def test_failed_observation_retry_and_restart(pair,monkeypatch,failures):
    pair.start();pair.deliver();c=pair.nodes['bob'][3];v=c.vault;_,_,old=seed(v)
    completed_until_claim(pair)
    assert 'secret_'+pair.sid not in v.entries
    before=deepcopy(pair.state('bob'));ops_before=deepcopy(pair.nodes['bob'][1].operations(pair.sid,private=True))
    state=fault(monkeypatch,v);state['enabled']=True
    sid='secret_'+pair.sid
    expected=deepcopy(pair.nodes['alice'][3].vault.entries[sid])
    for attempt in range(failures):
        with pytest.raises(OSError,match='injected vault'):c.tick_one(pair.sid)
        assert sid not in disk(v).entries and v.path.read_bytes()==state['old']
        assert pair.state('bob')==before and pair.nodes['bob'][1].operations(pair.sid,private=True)==ops_before
        assert state['hits']==attempt+1 and not list(v.path.parent.glob('.swapnet-*'));old_survives(v,old)
    state['enabled']=False
    # Observe whether the *same coordinator tick* retries the save. No manual
    # vault.save here: doing so would conceal the caller's retry behavior.
    c.tick_one(pair.sid)
    after=deepcopy(pair.state('bob'));assert after['secret_exposed']
    assert v.entries[sid]==expected
    assert disk(v).entries[sid]==expected
    old_survives(v,old);funding_before=len(pair.a.records)+len(pair.b.records)
    pair.restart('bob');c=pair.nodes['bob'][3]
    # Check before any chain observation: reopening alone must retain the secret.
    assert c.vault.entries[sid]==expected
    assert c.vault.secret(pair.sid,after['agreement']['long_leg']['hashlock']).hex()==expected['preimage']
    assert len(pair.a.records)+len(pair.b.records)==funding_before
    old_survives(c.vault,old)
    pair.restart('bob');assert pair.nodes['bob'][3].vault.entries[sid]==expected

@pytest.mark.skipif(os.name=='nt',reason='Directory fsync is a POSIX-only writer step')
def test_directory_sync_failure_retry_preserves_secret(pair,monkeypatch):
    import stat
    pair.start();pair.deliver();c=pair.nodes['bob'][3];v=c.vault;_,_,old=seed(v)
    completed_until_claim(pair);sid='secret_'+pair.sid
    expected=deepcopy(pair.nodes['alice'][3].vault.entries[sid])
    before=deepcopy(pair.state('bob'));real=os.fsync;state={'enabled':True,'hits':0,'directory_calls':0}
    def fsync(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            state['directory_calls']+=1
            if state['enabled']:
                state['hits']+=1;raise OSError('injected directory sync failure')
        return real(fd)
    with monkeypatch.context() as scope:
        scope.setattr(vault_module.os,'fsync',fsync)
        with pytest.raises(OSError,match='injected directory sync'):c.tick_one(pair.sid)
        assert state['hits']==1 and pair.state('bob')==before
        # Replacement already happened: disk can contain the new entry even
        # though directory sync failed. Neither success nor power-loss safety
        # is claimed until the same caller retries successfully.
        assert disk(v).entries[sid]==expected;old_survives(v,old)
        state['enabled']=False;c.tick_one(pair.sid)
        assert state['directory_calls']==2
    assert disk(v).entries[sid]==expected;pair.restart('bob')
    assert pair.nodes['bob'][3].vault.entries[sid]==expected


def test_existing_observed_secret_is_not_replaced(pair,monkeypatch):
    pair.start();pair.deliver();c=pair.nodes['bob'][3];v=c.vault;_,_,old=seed(v)
    completed_until_claim(pair);c.tick_one(pair.sid)
    entries=deepcopy(v.entries);raw=v.path.read_bytes()
    def unexpected_save():raise AssertionError('Existing durable secret must not be rewritten')
    monkeypatch.setattr(v,'save',unexpected_save)
    c.tick_one(pair.sid)
    assert v.entries==entries and v.path.read_bytes()==raw
    old_survives(v,old)

def test_wrong_observed_secret_refuses_without_vault_change(pair,monkeypatch):
    from dataclasses import replace
    pair.start();pair.deliver();c=pair.nodes['bob'][3];v=c.vault;_,_,old=seed(v)
    completed_until_claim(pair)
    entries=deepcopy(v.entries);raw=v.path.read_bytes();state=deepcopy(pair.state('bob'))
    d=c.drivers[B];observe=d.observe
    def wrong(*args,**kwargs):return replace(observe(*args,**kwargs),preimage='00'*32)
    monkeypatch.setattr(d,'observe',wrong)
    with pytest.raises(SwapError,match='PREIMAGE'):c.tick_one(pair.sid)
    assert v.entries==entries and v.path.read_bytes()==raw and pair.state('bob')==state
    old_survives(v,old)
