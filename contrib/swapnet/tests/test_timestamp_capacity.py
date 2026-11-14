"""Real coordinator/SQLite, simulated external EVM finality; no native chain claim."""
from dataclasses import asdict,replace
import json
from pathlib import Path
import pytest
import test_execution_v2 as te
from test_maker_terminal_capacity import maker_state,fresh_proposal
from swapnet.errors import SwapError

@pytest.fixture
def evm_pair(tmp_path,monkeypatch):
    original=te.Driver
    class FinalityDriver(original):
        def verify_reference(self,sid,terms,ref):
            # Simulator binds the reference to this fixture's exact contract;
            # production EVM ABI/address/lock-id verification is not exercised.
            assert ref['lock_id']==sid and ref['salt']=='bb'*32
            assert self.ledger.records[ref['txid']]['terms']==asdict(terms)
            return True
        def observe(self,t,ref):
            r=super().observe(t,ref)
            if self.family=='evm':r=replace(r,observation=replace(r.observation,finalized=getattr(self.ledger,'finalized',False)))
            return r
    monkeypatch.setattr(te,'A','evm:'+'44'*32+':31337:native')
    monkeypatch.setattr(te,'B','btx:'+te.NETWORK+':0:native')
    monkeypatch.setattr(te,'Driver',FinalityDriver)
    # Existing fresh_proposal helper uses its imported asset names.
    import test_maker_terminal_capacity as mc
    monkeypatch.setattr(mc,'A',te.A);monkeypatch.setattr(mc,'B',te.B)
    p=te.Pair(tmp_path);yield p
    for n in list(p.nodes):p.close(n)

def refunded_remote(p,finalized=True):
    p.start();p.deliver();j=p.nodes['bob'][1];maker=p.nodes['bob'][3]
    state=p.state('bob');agr=state['agreement'];terms=agr['long_leg']
    assert terms['asset'].startswith('evm:') and terms['lock_domain']=='timestamp'
    ref={'txid':'aa'*32,'lock_id':p.sid,'salt':'bb'*32}
    p.a.records[ref['txid']]={'terms':terms,'state':'refunded','confirmations':1,'preimage':None}
    p.a.finalized=finalized;p.time.n=terms['lock_value']+1
    p.b.height=agr['short_leg']['lock_value']+1
    p.market['market']['expires_at']=p.time()+10000
    maker.receive_reference('alice',p.sid,{'agreement_id':state['agreement_id'],'leg':'a','reference':ref})
    return maker

def accounting(p):
    st,j,_,_=p.nodes['bob'];s=p.state('bob')
    mid=st.db.execute('SELECT mandate_id FROM reservations WHERE id=?',(s['reservation_id'],)).fetchone()[0]
    held=st.db.execute('SELECT held FROM mandates WHERE id=?',(mid,)).fetchone()[0]
    grant=st.db.execute('SELECT consumed,revoked FROM sn_grants WHERE id=?',(s['grant_id'],)).fetchone()
    return {**maker_state(p),'mandate_held':held,'grant_consumed':grant[0],'grant_revoked':grant[1]}

def test_finalized_evm_refund_releases_capacity_after_restart(evm_pair):
    p=evm_pair;m=refunded_remote(p);m.tick_one(p.sid);before=accounting(p)
    assert before['long_leg']['refunded'] and before['long_leg']['finalized']
    assert before['long_leg']['exact_terms'] and before['long_leg']['canonical']
    assert not before['operations'] and not before['maker_funding_prepared']
    p.restart('bob');p.nodes['bob'][3].tick_one(p.sid);after=accounting(p)
    for k in ['stage','reservation','active','mandate_held','grant_revoked']:assert after[k]==before[k]
    st,j,_,m=p.nodes['bob']
    for n in range(1,128):j.save(f'{n:064x}',{'stage':'committed','principal':'fixture','peer':'fixture'})
    sid,proposal=fresh_proposal(p)
    try:m.receive_proposal('alice',sid,proposal,p.market);admission='accepted'
    except SwapError as e:admission=e.code
    print('MEASURED',json.dumps({'before':before,'after_restart':after,'fresh_admission_at_127_other_slots':admission}))
    assert after['stage']=='cancelled' and after['reservation']=='closed'
    assert after['mandate_held']=='0' and after['grant_revoked']==1
    assert admission=='accepted'

@pytest.mark.parametrize('funded',[False,True])
def test_nonfinal_or_durable_local_funding_stays_held(evm_pair,funded):
    p=evm_pair;m=refunded_remote(p,finalized=funded)
    if funded:p.nodes['bob'][1].prepare(p.sid,te.B,'fund','88'*32,'00')
    m.tick_one(p.sid);p.restart('bob');p.nodes['bob'][3].tick_one(p.sid)
    s=accounting(p);assert s['stage']=='committed' and s['reservation']=='held'
    assert int(s['mandate_held'])>0 and s['grant_revoked']==0
    if funded:assert s['operations']==['fund']
    else:assert not s['long_leg']['finalized']

@pytest.mark.parametrize('change',[{'canonical':False},{'exact_terms':False},{'conflicting':True},{'observed_at':0}])
def test_invalid_refund_observation_keeps_position(evm_pair,monkeypatch,change):
    p=evm_pair;m=refunded_remote(p)
    def install(m):
        driver=m.drivers[te.A];original=driver.observe
        def altered(*a,**kw):
            r=original(*a,**kw)
            return replace(r,observation=replace(r.observation,**change))
        monkeypatch.setattr(driver,'observe',altered)
    def checked_tick(m):
        if 'observed_at' in change:
            with pytest.raises(SwapError,match='Leg observation stale'):m.tick_one(p.sid)
        else:m.tick_one(p.sid)
    install(m);checked_tick(m);p.restart('bob');m=p.nodes['bob'][3];install(m);checked_tick(m)
    s=accounting(p)
    assert s['stage']==('reconciling' if change.get('conflicting') else 'committed')
    assert s['reservation']=='held' and s['active']==1
    assert int(s['mandate_held'])>0 and not s['grant_revoked']

def test_later_remote_reorg_cannot_reauthorize_cancelled_maker(evm_pair):
    p=evm_pair;m=refunded_remote(p);m.tick_one(p.sid)
    assert p.state('bob')['stage']=='cancelled'
    p.a.rollback_spend();p.restart('bob');p.nodes['bob'][3].tick_one(p.sid)
    s=accounting(p);assert s['stage']=='cancelled' and s['reservation']=='closed'
    assert s['mandate_held']=='0' and s['grant_revoked']==1 and not s['operations']
