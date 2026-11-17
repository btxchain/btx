"""Negotiation interruption recovery: real SQLite/processes, simulated chains/signers."""
from dataclasses import asdict
from pathlib import Path
import hashlib,json,multiprocessing,os,sqlite3
import pytest
from test_runtime_recovery_v2 import apps
from test_execution_v2 import A,B,NETWORK,Driver
from swapnet.application import Application
from swapnet.authorization import Principal
from swapnet.store import Store
from swapnet.vault import ForeignKeyVault
from swapnet.canonical import loads,dumps,digest
from swapnet.errors import SwapError
from swapnet.policy import Mandate

def prepare(apps,lifetime=10000,total='10000000'):
 nodes,time,ledgers,wire,deliver,step=apps;mids={}
 for n,asset in [('alice',A),('bob',B)]:
  m=Mandate(n,asset,total if n=='alice' else '10000000','10000' if n=='alice' and total=='10500' else '100000','1000',time()+lifetime,'66'*32)
  mids[n]=nodes[n].rpc(Principal(n,True),'createswapmandate',{'mandate':asdict(m)})['mandate_id']
 market={'sell_asset':A,'buy_asset':B,'numerator':'2','denominator':'1','maker_fee_atoms':'10','max_receive_network_fee_atoms':'100','max_input_atoms':'100000','expires_at':time()+10000}
 nodes['bob'].rpc(Principal('bob',True),'setswapmarket',{'market':market,'mandate_id':mids['bob'],'max_local_fee_atoms':'500','refund_fee_atoms':'100','claim_fee_atoms':'100'})
 deliver();rfq=nodes['alice'].rpc(Principal('alice'),'requestswapquote',{'sell_asset':A,'buy_asset':B,'sell_atoms':'10000'})
 for _ in range(4):step()
 quotes=nodes['alice'].rpc(Principal('alice'),'getswapquotes',{'request_id':rfq['request_id']})['quotes'];assert quotes
 params={'quote_id':quotes[0]['id'],'mandate_id':mids['alice'],'max_local_fee_atoms':'500','refund_fee_atoms':'100'}
 return params,mids['alice']

def kind(item):return loads(item[2])['packet']['body']['kind']
def packets(app,k):return [loads(r[0]) for r in app.store.db.execute('SELECT body FROM sn_outbox') if loads(r[0])['body']['kind']==k]
def snapshot(app,sid):
 s=app.journal.load(sid)[1]
 return {'proposal':s['proposal'],'keys':s['keys'],'reservation':s['reservation_id'],'signatures':s.get('signatures'),
 'grants':[list(r) for r in app.store.db.execute('SELECT id FROM sn_grants WHERE swap_id=?',(sid,))],
 'budgets':[list(r) for r in app.store.db.execute('SELECT held,used FROM mandates ORDER BY id')],
 'secret_hash':hashlib.sha256(json.dumps(app.vault.entries,sort_keys=True).encode()).hexdigest()}
def capture(apps,incoming):
 nodes,time,ledgers,wire,deliver,step=apps;params,mid=prepare(apps)
 sid=nodes['alice'].rpc(Principal('alice'),'acceptswapquote',params)['swap_id']
 for _ in range(12):
  while wire:
   item=wire.pop(0)
   if kind(item)==incoming:return sid,item
   sender,command,raw=item;nodes['bob' if sender=='alice' else 'alice'].on_message(1,command,raw)
  for app in nodes.values():app.tick()
 raise AssertionError('Did not reach valid '+incoming)
def reopen(old,name,apps):
 nodes,time,ledgers,wire,*_=apps
 app=Application(Store(Path(old.vault.path).parent/'state.sqlite'),NETWORK,old.identity,ForeignKeyVault(old.vault.path,b'1'*32),
 {a:Driver(l,name) for a,l in ledgers.items()},lambda peer,command,raw:(wire.append((name,command,raw)) or True),clock=time,policy=old.coordinator.policy)
 app.peer_connected(1);return app

def interrupted(apps,name,sid,command,raw,response,cut='response'):
 old=apps[0][name];old.close()
 def child():
  app=reopen(old,name,apps);original=app.coordinator.emit
  def cut_emit(recipient,k,*args):
   if k==response and cut=='response':
    s=app.journal.load(sid)[1];assert s['stage']==('committed' if name=='alice' else 'offered')
    assert not packets(app,response)
    os._exit(73)
   return original(recipient,k,*args)
  app.coordinator.emit=cut_emit
  if cut=='receipt':
   process=app._process
   def stop_after_handler(body):
    process(body)
    assert packets(app,response)
    os._exit(73)
   app._process=stop_after_handler
  app.on_message(1,command,raw);os._exit(74)
 process=multiprocessing.get_context('fork').Process(target=child);process.start();process.join(10)
 if process.is_alive():process.kill();process.join();pytest.fail('Child exceeded10s')
 assert process.exitcode==73
 apps[0][name]=app=reopen(old,name,apps);return app

def setup_message(apps,incoming):
 sid,item=capture(apps,incoming)
 _,command,raw=item
 name='alice' if incoming=='agreement' else 'bob'
 response='commit' if incoming=='agreement' else 'agreement'
 mid=digest('BTX/SWAPNET/PACKET/2',loads(raw)['packet'])
 return sid,name,response,mid,command,raw

def finish(apps,sid):
 nodes,time,ledgers,wire,deliver,step=apps
 for _ in range(40):step()
 assert all(app.journal.load(sid)[1]['stage']=='complete' for app in nodes.values())
 assert len(ledgers[A].records)==len(ledgers[B].records)==1

def financial_payload(app,sid,response):
 s=app.journal.load(sid)[1]
 if response=='agreement':return {'agreement':s['agreement'],'responder_signature':s['signatures']['responder']}
 return {'agreement_id':s['agreement_id'],'signatures':s['signatures']}

def prohibit_new_intent(app,monkeypatch):
 def forbidden(*args,**kwargs):pytest.fail('Replay created new financial intent')
 for driver in app.drivers.values():monkeypatch.setattr(driver,'new_key',forbidden)
 monkeypatch.setattr(app.vault,'new_secret',forbidden)
 monkeypatch.setattr(app.coordinator,'_deadlines',forbidden)
 monkeypatch.setattr(app.coordinator,'_save_new',forbidden)
 sign=app.identity.sign
 def envelope_only(message):
  assert message.startswith('BTX/SWAPNET/ENVELOPE/2:'),'Replay signed a new financial agreement'
  return sign(message)
 monkeypatch.setattr(app.identity,'sign',envelope_only)

@pytest.mark.skipif(os.name=='nt',reason='Deliberate abrupt child exit requires fork')
@pytest.mark.parametrize('incoming',['proposal','agreement'])
@pytest.mark.parametrize('cut',['response','receipt'])
def test_interrupted_negotiation_replays_saved_response(apps,monkeypatch,incoming,cut):
 sid,name,response,mid,command,raw=setup_message(apps,incoming)
 app=interrupted(apps,name,sid,command,raw,response,cut)
 assert app.journal.seen(mid,app.now()+60,app.now())
 assert not app.journal.commit_completed(mid)
 before=snapshot(app,sid);expected=financial_payload(app,sid,response)
 with monkeypatch.context() as m:
  prohibit_new_intent(app,m)
  app.on_message(1,command,raw)
 assert packets(app,response),'Admitted negotiation must recover its missing response'
 assert all(p['body']['payload']==expected for p in packets(app,response))
 assert snapshot(app,sid)==before and app.journal.commit_completed(mid)
 # Completed duplicates must not rerun even when a new envelope could be made.
 def no_handler(body):pytest.fail('Completed message processed twice')
 with monkeypatch.context() as m:
  m.setattr(app,'_process',no_handler);app.on_message(1,command,raw)
 finish(apps,sid)

@pytest.mark.parametrize('incoming',['proposal','agreement'])
@pytest.mark.parametrize('fault',['response','receipt'])
def test_failed_response_or_receipt_retry_keeps_intent(apps,monkeypatch,incoming,fault):
 sid,name,response,mid,command,raw=setup_message(apps,incoming);app=apps[0][name]
 table='sn_outbox' if fault=='response' else 'sn_commit_receipts'
 condition=" WHEN json_extract(CAST(NEW.body AS TEXT),'$.body.kind')='"+response+"'" if fault=='response' else ''
 app.store.db.execute('CREATE TRIGGER fail_save BEFORE INSERT ON '+table+condition+" BEGIN SELECT RAISE(ABORT,'save fault'); END")
 with pytest.raises(sqlite3.IntegrityError,match='save fault'):app.on_message(1,command,raw)
 assert not app.store.db.execute('SELECT 1 FROM sn_inbox WHERE id=?',(mid,)).fetchone()
 assert not app.journal.commit_completed(mid)
 before=snapshot(app,sid);expected=financial_payload(app,sid,response)
 app.store.db.execute('DROP TRIGGER fail_save');app.close();apps[0][name]=app=reopen(app,name,apps)
 with monkeypatch.context() as m:
  prohibit_new_intent(app,m)
  app.on_message(1,command,raw)
 assert snapshot(app,sid)==before
 assert all(p['body']['payload']==expected for p in packets(app,response))
 assert app.journal.commit_completed(mid)
 finish(apps,sid)

@pytest.mark.parametrize('incoming',['proposal','agreement'])
def test_ack_failure_keeps_completion_after_restart(apps,monkeypatch,incoming):
 sid,name,response,mid,command,raw=setup_message(apps,incoming);app=apps[0][name];original=app.emit
 def fail_ack(recipient,k,*args):
  if k=='ack':raise OSError('ack fault')
  return original(recipient,k,*args)
 with monkeypatch.context() as m:
  m.setattr(app,'emit',fail_ack)
  with pytest.raises(OSError,match='ack fault'):app.on_message(1,command,raw)
 assert app.journal.commit_completed(mid)
 before=snapshot(app,sid);outgoing=packets(app,response)
 app.close();apps[0][name]=app=reopen(app,name,apps)
 def no_handler(body):pytest.fail('ACK failure erased completed handling')
 monkeypatch.setattr(app,'_process',no_handler)
 app.on_message(1,command,raw)
 assert app.journal.commit_completed(mid) and snapshot(app,sid)==before
 assert packets(app,response)==outgoing
 assert any(p['body']['payload'].get('message_id')==mid for p in packets(app,'ack'))
 monkeypatch.undo();finish(apps,sid)

@pytest.mark.parametrize('incoming',['proposal','agreement'])
def test_legacy_admission_without_handler_completion(apps,incoming):
 sid,name,response,mid,command,raw=setup_message(apps,incoming);app=apps[0][name]
 assert not app.journal.seen(mid,loads(raw)['packet']['body']['expires_at'],app.now())
 app.close();apps[0][name]=app=reopen(app,name,apps)
 app.on_message(1,command,raw)
 assert packets(app,response) and app.journal.commit_completed(mid)
 finish(apps,sid)

def test_declined_proposal_is_completed_and_deduplicated(apps,monkeypatch):
 sid,name,response,mid,command,raw=setup_message(apps,'proposal');app=apps[0][name]
 monkeypatch.setattr(app,'markets',lambda:[])
 app.on_message(1,command,raw)
 assert packets(app,'decline')[0]['body']['payload']['code']=='MARKET_UNAVAILABLE'
 assert not packets(app,'agreement') and app.journal.commit_completed(mid)
 before=packets(app,'decline')
 monkeypatch.setattr(app,'_process',lambda body:pytest.fail('Decline processed twice'))
 app.on_message(1,command,raw)
 assert packets(app,'decline')==before and not apps[2][A].records and not apps[2][B].records

@pytest.mark.skipif(os.name=='nt',reason='Deliberate abrupt child exit requires fork')
def test_original_refund_survives_waiting_for_replay(apps):
 sid,name,response,mid,command,raw=setup_message(apps,'agreement')
 app=interrupted(apps,name,sid,command,raw,response)
 nodes,time,ledgers,wire,deliver,step=apps
 # Keep the original agreement offline: local funding may progress, never twice.
 for _ in range(12):
  app.tick();wire.clear()
  for ledger in ledgers.values():ledger.mine()
  time.n+=1
 assert len(ledgers[A].records)==1 and not ledgers[B].records
 s=app.journal.load(sid)[1];txid=s['refs']['a']['txid'];fund=ledgers[A].transactions[txid]
 refund=app.store.db.execute('SELECT txid,raw FROM sn_operations WHERE id=?',(s['refund_op'],)).fetchone()
 before=snapshot(app,sid);deadline=s['agreement']['long_leg']['lock_value']
 ledgers[A].height=deadline-1
 with pytest.raises(SwapError,match='REFUND_EARLY'):app.coordinator.request_refund(Principal('alice'),sid)
 assert snapshot(app,sid)==before
 ledgers[A].height=deadline;app.coordinator.request_refund(Principal('alice'),sid)
 ledgers[A].mine(3);app.coordinator.tick_one(sid)
 assert app.journal.load(sid)[1]['stage']=='refunded'
 assert app.store.db.execute('SELECT txid,raw FROM sn_operations WHERE id=?',(s['refund_op'],)).fetchone()==refund
 assert ledgers[A].transactions[txid]==fund and len(ledgers[A].records)==1 and not ledgers[B].records
 assert app.store.db.execute('SELECT held,used FROM mandates').fetchall()==[('0','10500')]
 assert app.store.db.execute('SELECT state FROM reservations WHERE id=?',(before['reservation'],)).fetchone()==('closed',)
 assert not app.journal.load(sid)[1]['secret_exposed']

@pytest.mark.parametrize('incoming',['proposal','agreement'])
def test_expired_or_bad_signature_replay_is_not_admitted(apps,incoming):
 sid,name,response,mid,command,raw=setup_message(apps,incoming);app=apps[0][name]
 wrapper=loads(raw);wrapper['packet']['signature']='invalid'
 with pytest.raises(SwapError):app.on_message(1,command,dumps(wrapper))
 assert not packets(app,response) and not app.journal.commit_completed(mid)
 apps[1].n=loads(raw)['packet']['body']['expires_at']+1
 with pytest.raises(SwapError,match='EXPIRED'):app.on_message(1,command,raw)
 assert not packets(app,response) and not app.journal.commit_completed(mid)
 assert not apps[2][A].records and not apps[2][B].records

