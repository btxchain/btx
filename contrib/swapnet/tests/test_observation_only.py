import json
from pathlib import Path
from decimal import Decimal
import pytest
import test_execution_v2 as te
from test_restored_history import History,Probe,TXID
from swapnet.store import Store
from swapnet.journal import Journal
from swapnet.authorization import Authority,Principal
from swapnet.coordinator import Coordinator
from swapnet.vault import ForeignKeyVault,atomic_private_write
from swapnet.recovery import export_bundle,restore_bundle
from swapnet.machine import LegObservation
from swapnet.drivers import Report
from swapnet.errors import SwapError
from swapnet.fee_bump import bump
from swapnet.application import Application
from dataclasses import asdict
from swapnet.policy import Mandate
from swapnet.quote import Quote
from swapnet.canonical import digest

@pytest.fixture
def restored(tmp_path,monkeypatch):
 monkeypatch.setattr(te,'A','btc:'+te.NETWORK+':0:native');monkeypatch.setattr(te,'B','btx:'+('22'*32)+':0:native')
 p=te.Pair(tmp_path);p.start();p.deliver();sid=p.sid;old=p.nodes['alice'][3];leg=p.state('alice')['agreement']['long_leg'];short=p.state('alice')['agreement']['short_leg'];folder=p.path/'alice';key=b'0123456789abcdef0123456789abcdef';atomic_private_write(folder/'vault.key',key);old.vault.save();(folder/'foreign-vault.json').write_bytes((folder/'vault.json').read_bytes());password='long owner fixture backup password';bundle=export_bundle(p.nodes['alice'][1],folder,password,te.NETWORK);p.close('alice');dest=tmp_path/'imported';restore_bundle(bundle['path'],dest,password,te.NETWORK)
 h=History('unique');h.script=leg['lock_commitment'];h.coin=Decimal(leg['amount_atoms'])/100000000;holder={};mode=['refunded'];effects=[]
 def open_c():
  st=Store(dest/'state.sqlite');j=Journal(st);auth=Authority(st,j,p.time);v=ForeignKeyVault(dest/'foreign-vault.json',key);inner=te.Driver(p.a,'alice');d=Probe(inner,h)
  d.new_key=inner.new_key;d.commitment=inner.commitment;d.ready=inner.ready;d.inventory=lambda:10**12
  def observe(t,ref):
   if ref is None or ref.get('txid')!=TXID:return inner.observe(t,ref)
   if mode[0]=='rpc_error':raise SwapError('CHAIN_RPC','unavailable')
   if mode[0]=='conflicting':return Report(LegObservation(True,True,False,2,False,False,False,True,p.time()),inner.clock())
   return Report(LegObservation(True,True,True,2,False,mode[0]=='claimed',mode[0]=='refunded',False,p.time()),inner.clock())
  d.observe=observe
  for name in ['prepare_funding','prepare_refund','finish_claim','broadcast']:
   def fail(*a,_name=name,**kw):effects.append(_name);raise AssertionError('spend '+_name)
   setattr(d,name,fail)
  c=Coordinator(j,auth,{te.A:d,te.B:te.Driver(p.b,'alice')},p.identities['alice'],v,lambda peer,kind,sid,body:p.queue.append(('alice',peer,kind,sid,body)),clock=p.time,policy=old.policy);p.nodes['alice']=(st,j,auth,c);holder.update(st=st,j=j,auth=auth,c=c,d=d);return c
 open_c();p.a.height=leg['lock_value']+1;p.b.height=short['lock_value']+1
 def snap():return {t:holder['st'].db.execute('SELECT * FROM '+t+' ORDER BY rowid').fetchall() for t in ['mandates','reservations','coinlocks','sn_operations','sn_grants']}
 def reopen():holder['st'].close();return open_c()
 yield p,sid,h,holder,mode,effects,snap,reopen
 for n in p.nodes:p.close(n)

@pytest.mark.parametrize('kind',['refunded','claimed','pending','unspent'])
def test_expired_facts_only(restored,kind):
 p,sid,h,o,m,e,snap,reopen=restored;m[0]=kind
 if kind=='unspent':h.add(TXID,0)
 before=snap();view=o['c'].resume(Principal('alice'),sid)
 expected={'refunded':'original_refunded','claimed':'original_claimed','pending':'spend_lookup_pending','unspent':'original_unspent'}[kind]
 assert view['recovery']['status']==expected and not view['recovery']['actions_enabled']
 assert view['recovery']['original']=={'txid':TXID,'vout':0}
 assert not view['refs'] and not view['funding_prepared'] and not view['funding_broadcast'] and not view['recovery_ready']
 assert snap()==before and not e
 c=reopen();v=c.resume(Principal('alice'),sid);assert v['recovery']['status']==expected and snap()==before and not e
 rev=o['j'].load(sid)[0];c.resume(Principal('alice'),sid);assert o['j'].load(sid)[0]==rev
 before_reads=h.history_calls;c.get(Principal('alice'),sid);c.list(Principal('alice'));assert h.history_calls==before_reads

@pytest.mark.parametrize('action',['cancel','peer_cancel','refund','bump_claim','bump_refund','prepare','fund','claim'])
def test_action_fences_before_first_tick(restored,action):
 from swapnet.terms import Agreement
 p,sid,h,o,m,e,snap,reopen=restored;c=o['c'];before=snap();rev,s=o['j'].load(sid)
 with pytest.raises(SwapError) as error:
  if action=='cancel':c.cancel(Principal('alice'),sid)
  elif action=='peer_cancel':c.receive_cancel('bob',sid,{'quote_id':s['quote_id']})
  elif action=='refund':c.request_refund(Principal('alice'),sid)
  elif action.startswith('bump'):bump(c,Principal('alice'),sid,action[5:],'101')
  else:getattr(c,'_'+action)(sid,s,rev,Agreement.parse(s['agreement']))
 assert error.value.code=='RECOVERY_READ_ONLY' and snap()==before and not e

@pytest.mark.parametrize('history',['missing','incomplete','ambiguous','empty'])
def test_history_failures_remain_readonly(restored,history):
 p,sid,h,o,m,e,snap,reopen=restored;h.mode=history;before=snap();v=o['c'].resume(Principal('alice'),sid)
 assert v['recovery']['status']=='unresolved' and not v['recovery']['actions_enabled']
 assert snap()==before and not e
 h.mode='unique';v=reopen().resume(Principal('alice'),sid);assert v['recovery']['status']=='original_refunded' and snap()==before


def test_latch_stays_after_height_rollback(restored):
 p,sid,h,o,m,e,snap,reopen=restored;before=snap();o['c'].resume(Principal('alice'),sid);p.a.height=100;p.b.height=100
 v=reopen().resume(Principal('alice'),sid);assert v['recovery']['mode']=='observation_only' and snap()==before and not e


def test_ownership(restored):
 p,sid,h,o,m,e,snap,reopen=restored
 with pytest.raises(SwapError,match='FORBIDDEN'):o['c'].resume(Principal('mallory'),sid)
 assert not e


def test_fresh_session_same_imported_database(restored):
 p,sid,h,o,m,e,snap,reopen=restored;c=o['c'];c.resume(Principal('alice'),sid);state=o['j'].load(sid)[1];rid=state['reservation_id'];gid=state['grant_id'];old=o['st'].db.execute('SELECT * FROM reservations WHERE id=?',(rid,)).fetchone();grant=o['st'].db.execute('SELECT * FROM sn_grants WHERE id=?',(gid,)).fetchone()
 # Restore ordinary component signing on this driver for the unrelated fresh agreement.
 d=o['d'];d.prepare_funding=Probe.prepare_funding.__get__(d);d.prepare_refund=Probe.prepare_refund.__get__(d);d.broadcast=Probe.broadcast.__get__(d)
 p.a.height=100;p.b.height=100 # New quote planned at current consistent clocks; old latch persists.
 mid=o['auth'].install(Principal('alice',True),asdict(Mandate('alice',te.A,'10000000','100000','1000',p.time()+100000,'77'*32)))
 nonce='66'*32;rfq={'network':te.NETWORK,'requester':digest('BTX/SWAPNET/REQUESTER/2',{'identity':'alice','nonce':nonce}),'sell_asset':te.A,'buy_asset':te.B,'sell_atoms':'10000','nonce':nonce,'issued_at':p.time(),'expires_at':p.time()+120};q=Quote(te.NETWORK,'bob',rfq['requester'],'88'*32,2,te.A,te.B,'10000','20000','10','100',p.time(),p.time()+120)
 fresh=c.start(Principal('alice'),{'quote':asdict(q),'signature':p.identities['bob'].sign(q.signing_message)},rfq,mid,'500','100')['swap_id'];p.deliver();assert fresh!=sid and not o['j'].setting('restored_session:'+fresh,False)
 calls=h.history_calls;c.resume(Principal('alice'),fresh);c.resume(Principal('alice'),fresh)
 assert o['j'].load(fresh)[1]['funding_broadcast'] and d.funding_calls==1 and h.history_calls==calls
 assert o['st'].db.execute('SELECT * FROM reservations WHERE id=?',(rid,)).fetchone()==old
 assert o['st'].db.execute('SELECT * FROM sn_grants WHERE id=?',(gid,)).fetchone()==grant
 assert c.get(Principal('alice'),sid)['recovery']['actions_enabled'] is False


def test_normal_fresh_cancellation(tmp_path,monkeypatch):
 monkeypatch.setattr(te,'A','btc:'+te.NETWORK+':0:native');monkeypatch.setattr(te,'B','btx:'+('22'*32)+':0:native');p=te.Pair(tmp_path)
 try:
  p.start();p.deliver();view=p.nodes['alice'][3].cancel(Principal('alice'),p.sid);assert view['stage']=='cancelled'
 finally:
  for n in p.nodes:p.close(n)


def test_owner_revocation_does_not_block_factual_reads(restored):
 p,sid,h,o,m,e,snap,reopen=restored;s=o['j'].load(sid)[1];rid=s['reservation_id'];mid=o['st'].db.execute('SELECT mandate_id FROM reservations WHERE id=?',(rid,)).fetchone()[0]
 o['auth'].revoke(Principal('alice',True),mid);before=snap();v=o['c'].resume(Principal('alice'),sid)
 assert v['recovery']['status']=='original_refunded' and snap()==before and not e


def test_reimport_retains_observation_only_latch(restored,tmp_path):
 p,sid,h,o,m,e,snap,reopen=restored;c=o['c'];c.resume(Principal('alice'),sid);password='long observation-only reexport password';folder=Path(o['st'].path).parent if hasattr(o['st'],'path') else tmp_path/'imported'
 b=export_bundle(o['j'],folder,password,te.NETWORK);dest=tmp_path/'again';restore_bundle(b['path'],dest,password,te.NETWORK);s=Store(dest/'state.sqlite')
 try:assert Journal(s).load(sid)[1]['recovery_facts']['mode']=='observation_only'
 finally:s.close()


def test_peer_hint_cannot_enable_actions(restored):
 p,sid,h,o,m,e,snap,reopen=restored;c=o['c'];c.resume(Principal('alice'),sid);state=o['j'].load(sid)[1];before=snap();original=state['recovery_facts']['original']
 c.receive_reference('bob',sid,{'agreement_id':state['agreement_id'],'leg':'b','reference':{'txid':'cd'*32,'vout':0}})
 c.tick_one(sid);assert c.get(Principal('alice'),sid)['recovery']['original']==original and not e
 assert snap()==before


def test_imported_prepared_recovery_is_not_fenced(tmp_path,monkeypatch):
 monkeypatch.setattr(te,'A','btc:'+te.NETWORK+':0:native');monkeypatch.setattr(te,'B','btx:'+('22'*32)+':0:native');p=te.Pair(tmp_path)
 try:
  p.start();p.deliver();c=p.nodes['alice'][3];c.tick_one(p.sid);c.tick_one(p.sid);p.a.mine(2)
  state=p.state('alice');ref=state['refs']['a'];assert state['funding_broadcast'] and state['refund_op']
  folder=p.path/'alice';key=b'0123456789abcdef0123456789abcdef';atomic_private_write(folder/'vault.key',key);c.vault.save();(folder/'foreign-vault.json').write_bytes((folder/'vault.json').read_bytes());password='long prepared recovery fixture password';bundle=export_bundle(p.nodes['alice'][1],folder,password,te.NETWORK);policy=c.policy;p.close('alice');dest=tmp_path/'prepared';restore_bundle(bundle['path'],dest,password,te.NETWORK)
  st=Store(dest/'state.sqlite');j=Journal(st);a=Authority(st,j,p.time);v=ForeignKeyVault(dest/'foreign-vault.json',key);c=Coordinator(j,a,{te.A:te.Driver(p.a,'alice'),te.B:te.Driver(p.b,'alice')},p.identities['alice'],v,lambda *a:None,clock=p.time,policy=policy);p.nodes['alice']=(st,j,a,c)
  p.a.height=state['agreement']['long_leg']['lock_value']+1;p.b.height=state['agreement']['short_leg']['lock_value']+1
  c.request_refund(Principal('alice'),p.sid)
  recovered=p.state('alice');assert recovered['stage']=='refund_broadcast' and recovered['refs']['a']==ref
  assert not recovered.get('recovery_facts') and len([x for x in j.operations(p.sid) if x['kind']=='fund'])==1
 finally:
  for n in p.nodes:p.close(n)


def test_discovery_latch_save_failure_does_not_enable_actions(restored):
 p,sid,h,o,m,e,snap,reopen=restored;before=snap();original=o['j'].save
 def failed(*a,**kw):raise RuntimeError('save failed')
 o['j'].save=failed
 with pytest.raises(RuntimeError,match='save failed'):o['c'].resume(Principal('alice'),sid)
 assert snap()==before and not e
 o['j'].save=original
 with pytest.raises(SwapError,match='RECOVERY_READ_ONLY'):o['c'].cancel(Principal('alice'),sid)
 view=reopen().resume(Principal('alice'),sid)
 assert view['recovery']['status']=='original_refunded' and snap()==before and not e


@pytest.mark.parametrize('failure',['rpc_error','conflicting'])
def test_last_verified_facts_survive_current_uncertainty(restored,failure):
 p,sid,h,o,m,e,snap,reopen=restored;c=o['c'];before=snap();v=c.resume(Principal('alice'),sid);verified=v['recovery']['last_verified'];assert verified['status']=='original_refunded'
 m[0]=failure;v=c.resume(Principal('alice'),sid)
 assert v['recovery']['status']==('unresolved' if failure=='rpc_error' else 'conflicting')
 assert v['recovery']['last_verified']==verified and not v['recovery']['actions_enabled']
 v=reopen().resume(Principal('alice'),sid);assert v['recovery']['last_verified']==verified and snap()==before and not e

@pytest.mark.parametrize('failure',['io','revision'])
def test_fact_save_failure_keeps_latch_and_retries(restored,failure):
 p,sid,h,o,m,e,snap,reopen=restored;before=snap();save=o['j'].save
 def fail(session,body,*a,**kw):
  if body.get('recovery_facts',{}).get('original'):
   if failure=='revision':raise SwapError('REVISION_CONFLICT','simulated conflict')
   raise RuntimeError('facts save failed')
  return save(session,body,*a,**kw)
 o['j'].save=fail
 with pytest.raises((RuntimeError,SwapError)):o['c'].resume(Principal('alice'),sid)
 assert o['j'].load(sid)[1]['recovery_facts']['mode']=='observation_only'
 assert snap()==before and not e
 view=reopen().resume(Principal('alice'),sid);assert view['recovery']['status']=='original_refunded' and snap()==before
