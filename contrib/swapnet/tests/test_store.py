import dataclasses,threading
import pytest
from swapnet.store import Store
from swapnet.errors import SwapError
from conftest import NOW

def install(s,m):return s.install_mandate(m,owner_authorized=True)
def test_owner_required(store,mandate):
    with pytest.raises(SwapError):store.install_mandate(mandate,owner_authorized=False)
def test_idempotent_reservation(store,mandate,quote):
    mid=install(store,mandate)
    a=store.reserve(quote,mid,'agent','100',NOW)
    assert a==store.reserve(quote,mid,'agent','100',NOW)
    assert store.db.execute('SELECT held FROM mandates').fetchone()[0]=='10100'
    with pytest.raises(SwapError):store.reserve(quote,mid,'agent','101',NOW)
def test_cumulative_limit(store,mandate,quote):
    mid=install(store,mandate)
    for n in range(2):store.reserve(dataclasses.replace(quote,nonce=format(n,'064x')),mid,'agent','100',NOW)
    with pytest.raises(SwapError):store.reserve(dataclasses.replace(quote,nonce='f'*64),mid,'agent','100',NOW)
def test_revocation_recovery(store,mandate,quote):
    mid=install(store,mandate);rid=store.reserve(quote,mid,'agent','100',NOW)
    store.mark_funded(rid);store.revoke(mid,owner_authorized=True)
    with pytest.raises(SwapError):store.reserve(dataclasses.replace(quote,nonce='f'*64),mid,'agent','100',NOW)
    with pytest.raises(SwapError):store.settle_reservation(rid,'50')
    store.settle_reservation(rid,'50',verified_terminal=True)
    assert store.db.execute('SELECT held,used FROM mandates').fetchone()==('0','50')
def test_exclusive_coin_lock(store,mandate,quote):
    mid=install(store,mandate);a=store.reserve(quote,mid,'agent','100',NOW)
    b=store.reserve(dataclasses.replace(quote,nonce='f'*64),mid,'agent','100',NOW)
    store.lock_coins(a,'btc',['a:0']);store.lock_coins(a,'btc',['a:0'])
    with pytest.raises(SwapError):store.lock_coins(b,'btc',['a:0'])
def test_concurrent_reservation(store,mandate,quote):
    mid=install(store,dataclasses.replace(mandate,max_total_atoms='11000'))
    outcomes=[]
    def run(n):
        try:store.reserve(dataclasses.replace(quote,nonce=format(n,'064x')),mid,'agent','100',NOW);outcomes.append('ok')
        except SwapError:outcomes.append('denied')
    threads=[threading.Thread(target=run,args=(i,)) for i in range(8)]
    for t in threads:t.start()
    for t in threads:t.join()
    assert outcomes.count('ok')==1 and outcomes.count('denied')==7

def test_restart_persistence(tmp_path,mandate,quote):
    s=Store(tmp_path/'state.sqlite');mid=install(s,mandate);rid=s.reserve(quote,mid,'agent','100',NOW);head=s.verify_audit();s.close()
    s=Store(tmp_path/'state.sqlite');assert s.reserve(quote,mid,'agent','100',NOW)==rid;assert s.verify_audit()==head;s.close()
def test_cas_and_secret_irreversibility(store):
    sid='1'*64;assert store.save_session(sid,{'secret_exposed':False})==0
    with pytest.raises(SwapError):store.save_session(sid,{'secret_exposed':True},-1)
    assert store.save_session(sid,{'secret_exposed':True},0)==1
    with pytest.raises(SwapError):store.save_session(sid,{'secret_exposed':False},1)
def test_immutable_outbox_and_retry(store):
    op,tx='1'*64,'2'*64;store.prepare_operation(op,'btc','fund',tx,'deadbeef')
    with pytest.raises(SwapError):store.prepare_operation(op,'btc','fund',tx,'cafe')
    def fail(raw):raise TimeoutError('ambiguous')
    with pytest.raises(TimeoutError):store.broadcast_operation(op,fail)
    seen=[]
    assert store.broadcast_operation(op,lambda raw:seen.append(raw) or tx)==tx
    assert store.broadcast_operation(op,lambda raw:(_ for _ in ()).throw(Exception()))==tx
    assert seen==['deadbeef']
def test_corrupt_audit_detected(store,mandate):
    install(store,mandate);store.db.execute("UPDATE audit SET body='{}'")
    with pytest.raises((SwapError,TypeError)):store.verify_audit()
