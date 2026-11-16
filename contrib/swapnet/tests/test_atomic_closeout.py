"""Atomic unfunded termination and conservative old-state recovery; no native chains."""
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
import json
import shutil
import sqlite3
import pytest
from swapnet.authorization import Principal
from swapnet.errors import SwapError
from swapnet.quote import Quote
from test_execution_v2 import Pair

@contextmanager
def session(path,kind,committed=False):
    assert shutil.disk_usage(path.parent).free>1.25*1024**3
    path.mkdir(mode=0o700);p=Pair(path)
    try:
        p.start()
        if kind=='cancel' or committed:p.deliver()
        yield p
    finally:
        for n in p.nodes:p.close(n)
        for name in ('alice','bob'):
            for suffix in ('','-wal','-shm'):
                f=path/name/('state.db'+suffix)
                if f.exists():f.unlink()  # only this completed disposable test


def accounting(p,actor='alice'):
    st,j,auth,c=p.nodes[actor];s=p.state(actor);rid=s['reservation_id']
    mid,cost,state=st.db.execute('SELECT mandate_id,cost,state FROM reservations WHERE id=?',(rid,)).fetchone()
    held,used=st.db.execute('SELECT held,used FROM mandates WHERE id=?',(mid,)).fetchone()
    return {'held':int(held),'used':int(used),'cost':int(cost),'reservation':state,'stage':s['stage']}


def close_count(p,actor='alice'):
    rid=p.state(actor)['reservation_id']
    return sum(1 for (raw,) in p.nodes[actor][0].db.execute('SELECT body FROM audit')
               if (lambda x:x.get('type')=='reservation_closed' and x.get('id')==rid)(json.loads(raw)))


def terminate(p,kind,actor='alice'):
    c=p.nodes[actor][3]
    if kind=='cancel':return c.cancel(Principal(actor),p.sid)
    return c.receive_decline(p.state(actor)['peer'],p.sid,{'code':'UNAVAILABLE','message':'Legitimate proposal decline'})


def grant_rows(p,actor='alice'):
    return p.nodes[actor][0].db.execute('SELECT id,consumed,revoked FROM sn_grants WHERE swap_id=? ORDER BY id',(p.sid,)).fetchall()


@pytest.mark.parametrize('kind',['cancel','decline'])
def test_atomic_rollback_and_retry(tmp_path,kind):
    with session(tmp_path/'pair',kind) as p:
        st=p.nodes['alice'][0];before=accounting(p);grants=grant_rows(p)
        terminal='cancelled' if kind=='cancel' else 'rejected'
        st.db.execute("CREATE TEMP TRIGGER fail_terminal BEFORE UPDATE ON sn_negotiations "
          "WHEN NEW.id='"+p.sid+"' AND NEW.stage='"+terminal+"' "
          "BEGIN SELECT RAISE(ABORT,'injected terminal write failure'); END")
        with pytest.raises(sqlite3.IntegrityError,match='injected terminal write failure'):terminate(p,kind)
        assert accounting(p)==before  # release and session update must roll back together
        assert grant_rows(p)==grants and close_count(p)==0 and st.verify_audit()
        p.restart('alice');terminate(p,kind)
        after=accounting(p);assert after['stage']==terminal and after['reservation']=='closed'
        assert after['held']==0 and after['used']==0 and close_count(p)==1
        p.restart('alice');terminate(p,kind);assert accounting(p)==after and close_count(p)==1
        assert not p.a.records and not p.b.records and p.nodes['alice'][0].verify_audit()


@pytest.mark.parametrize('kind',['cancel','decline'])
def test_legacy_partial_recovery_preserves_other_budget(tmp_path,kind):
    with session(tmp_path/'pair',kind) as p:
        st,j,auth,c=p.nodes['alice'];s=p.state('alice');rid=s['reservation_id']
        mid=st.db.execute('SELECT mandate_id FROM reservations WHERE id=?',(rid,)).fetchone()[0]
        q=Quote.parse(s['quote']['quote'])
        used=st.reserve(replace(q,nonce='77'*32,sequence=2),mid,'alice','500',p.time())
        st.settle_reservation(used,'50')
        other=st.reserve(replace(q,nonce='88'*32,sequence=3),mid,'alice','500',p.time())
        # Recreate exactly the persisted legacy split state already reproduced:
        # release committed, terminal session save never committed.
        st.settle_reservation(rid,'0');before=accounting(p)
        assert before['reservation']=='closed' and before['held']>0 and before['used']==50
        totals=st.db.execute('SELECT id,held,used FROM mandates ORDER BY id').fetchall()
        assert close_count(p)==1
        p.restart('alice');terminate(p,kind)
        assert p.state('alice')['stage']==('cancelled' if kind=='cancel' else 'rejected')
        st=p.nodes['alice'][0];assert st.db.execute('SELECT id,held,used FROM mandates ORDER BY id').fetchall()==totals
        assert st.db.execute('SELECT state FROM reservations WHERE id=?',(other,)).fetchone()==('held',)
        assert close_count(p)==1
        p.restart('alice');terminate(p,kind);assert close_count(p)==1
        assert p.nodes['alice'][0].db.execute('SELECT id,held,used FROM mandates ORDER BY id').fetchall()==totals
        assert not p.nodes['alice'][1].operations(p.sid) and not p.a.records and not p.b.records
        assert p.nodes['alice'][0].verify_audit()


@pytest.mark.parametrize('actor',['alice','bob'])
def test_healthy_cancel_revokes_grant_and_repeats_once(tmp_path,actor):
    with session(tmp_path/'pair','cancel') as p:
        before=accounting(p,actor);assert grant_rows(p,actor)
        terminate(p,'cancel',actor);after=accounting(p,actor)
        assert after['held']==0 and after['used']==0 and after['reservation']=='closed'
        assert before['held']==before['cost'] and close_count(p,actor)==1
        assert all(not consumed and revoked for _,consumed,revoked in grant_rows(p,actor))
        p.restart(actor);terminate(p,'cancel',actor);assert accounting(p,actor)==after and close_count(p,actor)==1


@pytest.mark.parametrize('kind',['cancel','decline'])
@pytest.mark.parametrize('funded',[False,True])
def test_prepared_and_funded_refusal(tmp_path,kind,funded):
    with session(tmp_path/'pair',kind,committed=True) as p:
        c=p.nodes['alice'][3];c.tick_one(p.sid)
        if funded:c.tick_one(p.sid)
        before=accounting(p);ops=c.journal.operations(p.sid,private=True);grants=grant_rows(p)
        if kind=='cancel':
            with pytest.raises(SwapError,match='FUNDS_LOCKED'):terminate(p,kind)
        else:terminate(p,kind)
        assert accounting(p)==before and c.journal.operations(p.sid,private=True)==ops
        assert grant_rows(p)==grants and close_count(p)==0


@pytest.mark.parametrize('evidence',['operation','coinlock','consumed_grant','funded_reservation','own_reference'])
@pytest.mark.parametrize('closed',[False,True])
def test_hidden_recovery_obligations_refuse_close(tmp_path,evidence,closed):
    with session(tmp_path/'pair','cancel') as p:
        st,j,auth,c=p.nodes['alice'];s=p.state('alice');rid=s['reservation_id']
        if closed:st.settle_reservation(rid,'0')
        if evidence=='own_reference':
            rev,current=j.load(p.sid);current['refs']['a']={'txid':'99'*32,'vout':0};j.save(p.sid,current,rev)
        if evidence=='operation':j.prepare(p.sid,s['agreement']['long_leg']['asset'],'fund','99'*32,'00',{})
        if evidence=='coinlock':
            with st.transaction() as db:db.execute('INSERT INTO coinlocks VALUES(?,?,?)',(s['agreement']['long_leg']['asset'],'99:0',rid))
        if evidence=='consumed_grant':
            with st.transaction() as db:db.execute('UPDATE sn_grants SET consumed=1 WHERE id=?',(s['grant_id'],))
        if evidence=='funded_reservation':
            with st.transaction() as db:db.execute("UPDATE reservations SET state='funded' WHERE id=?",(rid,))
        before=accounting(p);grants=grant_rows(p);ops=j.operations(p.sid,private=True)
        with pytest.raises(SwapError,match='FUNDS_LOCKED'):terminate(p,'cancel')
        assert accounting(p)==before and grant_rows(p)==grants and j.operations(p.sid,private=True)==ops


@pytest.mark.parametrize('kind',['cancel','decline'])
def test_observation_only_not_closed(tmp_path,kind):
    with session(tmp_path/'pair',kind) as p:
        st,j,auth,c=p.nodes['alice'];rev,s=j.load(p.sid);s['recovery_facts']={'mode':'observation_only'};j.save(p.sid,s,rev)
        before=accounting(p)
        if kind=='cancel':
            with pytest.raises(SwapError,match='RECOVERY_READ_ONLY'):terminate(p,kind)
        else:terminate(p,kind)
        assert accounting(p)==before and close_count(p)==0


def test_stale_revision_cannot_release_budget(tmp_path,monkeypatch):
    with session(tmp_path/'pair','cancel') as p:
        st,j,auth,c=p.nodes['alice'];rev,s=j.load(p.sid)
        current=dict(s);current['last_action']='concurrent_update';j.save(p.sid,current,rev)
        monkeypatch.setattr(c,'_owned',lambda *args:(rev,s))
        before=accounting(p)
        with pytest.raises(SwapError,match='REVISION_CONFLICT'):terminate(p,'cancel')
        assert accounting(p)==before and close_count(p)==0


def test_wrong_owner_and_peer_do_not_close(tmp_path):
    with session(tmp_path/'pair','cancel') as p:
        c=p.nodes['alice'][3];before=accounting(p)
        with pytest.raises(SwapError,match='FORBIDDEN'):c.cancel(Principal('other'),p.sid)
        c.receive_decline('other',p.sid,{'code':'UNAVAILABLE','message':'unrelated'})
        assert accounting(p)==before and close_count(p)==0

@pytest.mark.parametrize('kind',['cancel','decline'])
def test_imported_unknown_bitcoin_payment_not_closed(tmp_path,kind):
    with session(tmp_path/'pair','cancel') as p:
        st,j,auth,c=p.nodes['bob'];s=p.state('bob')
        assert s['role']=='responder' and s['agreement']['short_leg']['asset'].startswith('btc:')
        j.set_setting('restored_session:'+p.sid,True)
        assert c._imported_unknown(p.sid,s)
        before=accounting(p,'bob')
        if kind=='cancel':
            with pytest.raises(SwapError,match='RECOVERY_READ_ONLY'):terminate(p,kind,'bob')
        else:terminate(p,kind,'bob')
        assert accounting(p,'bob')==before and close_count(p,'bob')==0


def test_unfunded_responder_with_counterparty_payment_can_cancel(tmp_path):
    with session(tmp_path/'pair','cancel') as p:
        alice=p.nodes['alice'][3];alice.tick_one(p.sid);alice.tick_one(p.sid);p.deliver()
        s=p.state('bob');assert s['refs'].get('a') and not s['refs'].get('b')
        assert not s['funding_prepared'] and not s['funding_broadcast']
        other_before=accounting(p,'alice');terminate(p,'cancel','bob')
        assert p.state('bob')['stage']=='cancelled' and close_count(p,'bob')==1
        assert accounting(p,'alice')==other_before and not p.b.records
