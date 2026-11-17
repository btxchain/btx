"""First outgoing proposal persistence/retry pilot; real SQLite, simulated chains."""
from dataclasses import asdict
from pathlib import Path
import json,sqlite3,hashlib
from copy import deepcopy
from dataclasses import replace
from swapnet.quote import Quote
import pytest
from test_runtime_recovery_v2 import apps
from test_execution_v2 import A,B,NETWORK,Driver
from swapnet.application import Application
from swapnet.authorization import Principal
from swapnet.store import Store
from swapnet.vault import ForeignKeyVault
from swapnet.policy import Mandate
from swapnet.canonical import dumps,loads,digest
from swapnet.errors import SwapError


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

def proposal_packets(app):
 return [loads(raw) for raw, in app.store.db.execute('SELECT body FROM sn_outbox') if loads(raw)['body']['kind']=='proposal']

def snapshot(app,sid):
 state=app.journal.load(sid)[1];db=app.store.db
 return {'sid':sid,'stage':state['stage'],'proposal_sha256':hashlib.sha256(dumps(state['proposal'])).hexdigest(),
         'keys_sha256':hashlib.sha256(dumps(state['keys'])).hexdigest(),
         'vault_entries_sha256':hashlib.sha256(json.dumps(app.vault.entries,sort_keys=True).encode()).hexdigest(),
         'reservation_ids':[r[0] for r in db.execute('SELECT id FROM reservations ORDER BY id')],
         'reservation_states':[r[0] for r in db.execute('SELECT state FROM reservations ORDER BY id')],
         'budgets':[list(r) for r in db.execute('SELECT held,used FROM mandates ORDER BY id')],
         'claimed_quotes':[list(r) for r in db.execute('SELECT quote_id,swap_id FROM sn_claimed_quotes')],
         'operation_count':db.execute('SELECT count(*) FROM sn_operations').fetchone()[0]}

def reopen_alice(apps):
 nodes,time,ledgers,wire,deliver,step=apps;old=nodes['alice'];old.close()
 nodes['alice']=alice=Application(Store(Path(old.vault.path).parent/'state.sqlite'),NETWORK,old.identity,
  ForeignKeyVault(old.vault.path,b'1'*32),{asset:Driver(ledger,'alice') for asset,ledger in ledgers.items()},
  lambda peer,command,raw:(wire.append(('alice',command,raw)) or True),clock=time,policy=old.coordinator.policy)
 alice.peer_connected(1);return alice

def fault(apps,**kwargs):
 params,mid=prepare(apps,**kwargs);alice=apps[0]['alice']
 alice.store.db.execute("CREATE TRIGGER reject_proposal BEFORE INSERT ON sn_outbox WHEN json_extract(CAST(NEW.body AS TEXT),'$.body.kind')='proposal' BEGIN SELECT RAISE(ABORT,'proposal fault'); END")
 with pytest.raises(sqlite3.IntegrityError,match='proposal fault'):alice.rpc(Principal('alice'),'acceptswapquote',params)
 sid=alice.store.db.execute('SELECT id FROM sn_negotiations').fetchone()[0]
 before=snapshot(alice,sid);assert before['stage']=='proposed' and before['reservation_states']==['held'] and not proposal_packets(alice)
 return params,mid,sid,before

def clear_fault(alice):alice.store.db.execute('DROP TRIGGER reject_proposal')
def finish(apps,sid):
 nodes,time,ledgers,wire,deliver,step=apps
 for _ in range(40):step()
 assert all(app.journal.load(sid)[1]['stage']=='complete' for app in nodes.values())
 assert len(ledgers[A].records)==len(ledgers[B].records)==1

def no_fresh_setup(alice,monkeypatch):
 def forbidden(*args,**kwargs):pytest.fail('Retry created a new financial intent')
 for driver in alice.drivers.values():monkeypatch.setattr(driver,'new_key',forbidden)
 monkeypatch.setattr(alice.vault,'new_secret',forbidden)
 monkeypatch.setattr(alice.coordinator,'_deadlines',forbidden)
 monkeypatch.setattr(alice.coordinator,'_save_new',forbidden)

@pytest.mark.parametrize('entry',['accept','resume'])
def test_missing_proposal_retry_and_reopen(apps,monkeypatch,entry):
 params,mid,sid,before=fault(apps);nodes,time,ledgers,wire,deliver,step=apps;alice=nodes['alice'];clear_fault(alice)
 if entry=='resume':alice=reopen_alice(apps)
 no_fresh_setup(alice,monkeypatch)
 if entry=='accept':result=alice.rpc(Principal('alice'),'acceptswapquote',params)
 else:result=alice.rpc(Principal('alice'),'resumeswap',{'swap_id':sid})
 assert result['swap_id']==sid and snapshot(alice,sid)==before
 packets=proposal_packets(alice);assert len(packets)==1,'Recovered intent must enter the outbox'
 assert packets[0]['body']['payload']==alice.journal.load(sid)[1]['proposal']
 finish(apps,sid)

@pytest.mark.parametrize('mode',['normal','not_due','acknowledged','beyond_page'])
def test_existing_exact_packet_is_not_recreated(apps,monkeypatch,mode):
 params,mid=prepare(apps);nodes,time,ledgers,wire,deliver,step=apps;alice=nodes['alice'];sid=alice.rpc(Principal('alice'),'acceptswapquote',params)['swap_id'];before=snapshot(alice,sid)
 packet=proposal_packets(alice)[0];packet_id=digest('BTX/SWAPNET/PACKET/2',packet)
 if mode=='not_due':alice.store.db.execute('UPDATE sn_outbox SET next_try=? WHERE id=?',(time()+10000,packet_id))
 elif mode=='acknowledged':alice.journal.ack(packet_id,'bob')
 elif mode=='beyond_page':
  with alice.store.transaction() as db:
   for i in range(40):
    other=deepcopy(packet);other['body']['swap_id']=format(i+100,'064x');oid=digest('BTX/SWAPNET/PACKET/2',other)
    db.execute('INSERT INTO sn_outbox VALUES(?,?,?,?,?,0,0)',(oid,'bob','swterms',dumps(other),0))
  assert packet_id not in [x[0] for x in alice.journal.due(time(),32)]
 queued=alice.store.db.execute('SELECT id FROM sn_outbox ORDER BY id').fetchall();seq=alice.store.db.execute('SELECT identity,n FROM sn_sequences ORDER BY identity').fetchall()
 no_fresh_setup(alice,monkeypatch)
 def no_sign(*args):pytest.fail('Queued proposal was signed again')
 monkeypatch.setattr(alice.identity,'sign',no_sign)
 alice.rpc(Principal('alice'),'acceptswapquote',params);alice.rpc(Principal('alice'),'resumeswap',{'swap_id':sid})
 assert snapshot(alice,sid)==before
 assert alice.store.db.execute('SELECT id FROM sn_outbox ORDER BY id').fetchall()==queued
 assert alice.store.db.execute('SELECT identity,n FROM sn_sequences ORDER BY identity').fetchall()==seq

@pytest.mark.parametrize('failure',['save_again','sign'])
def test_repeated_retry_failure_then_success(apps,monkeypatch,failure):
 params,mid,sid,before=fault(apps);alice=apps[0]['alice'];original=alice.identity.sign
 if failure=='sign':
  clear_fault(alice)
  def refused(*args):raise SwapError('TEST_SIGN','Temporary envelope signer refusal')
  monkeypatch.setattr(alice.identity,'sign',refused)
 with pytest.raises((sqlite3.IntegrityError,SwapError)):alice.rpc(Principal('alice'),'acceptswapquote',params)
 assert snapshot(alice,sid)==before and not proposal_packets(alice)
 if failure=='save_again':clear_fault(alice)
 else:monkeypatch.setattr(alice.identity,'sign',original)
 alice.rpc(Principal('alice'),'acceptswapquote',params);assert snapshot(alice,sid)==before and len(proposal_packets(alice))==1
 finish(apps,sid)

@pytest.mark.parametrize('field,value',[('mandate_id','77'*32),('max_local_fee_atoms','501'),('refund_fee_atoms','101'),('claim_fee_atoms','101')])
def test_changed_retry_parameters_refuse(apps,field,value):
 params,mid,sid,before=fault(apps);alice=apps[0]['alice'];clear_fault(alice);params[field]=value
 with pytest.raises(SwapError,match='IDEMPOTENCY_CONFLICT'):alice.rpc(Principal('alice'),'acceptswapquote',params)
 assert snapshot(alice,sid)==before and not proposal_packets(alice)

@pytest.mark.parametrize('state,code',[('revoked','MANDATE_EXPIRED'),('mandate_expired','MANDATE_EXPIRED'),('closed','RESERVATION'),('restored','RECOVERY_READ_ONLY'),('observation_only','RECOVERY_READ_ONLY'),('prepared','RECOVERY_CONFLICT')])
def test_missing_send_preserves_authority_and_recovery_fences(apps,state,code):
 params,mid,sid,before=fault(apps,lifetime=10 if state=='mandate_expired' else 10000);nodes,time,ledgers,wire,deliver,step=apps;alice=nodes['alice'];clear_fault(alice)
 if state=='revoked':alice.authority.revoke(Principal('alice',True),mid)
 elif state=='mandate_expired':time.n+=11
 elif state=='closed':alice.store.settle_reservation(before['reservation_ids'][0],'0')
 elif state=='restored':alice.journal.set_setting('restored_session:'+sid,True)
 else:
  rev,s=alice.journal.load(sid)
  if state=='observation_only':s['recovery_facts']={'mode':'observation_only'}
  else:s['funding_prepared']=True
  alice.journal.save(sid,s,rev)
 frozen=snapshot(alice,sid)
 with pytest.raises(SwapError,match=code):alice.rpc(Principal('alice'),'acceptswapquote',params)
 assert snapshot(alice,sid)==frozen and not proposal_packets(alice)
 assert not ledgers[A].records and not ledgers[B].records

def test_wrong_principal_cannot_resume(apps):
 params,mid,sid,before=fault(apps);alice=apps[0]['alice'];clear_fault(alice)
 with pytest.raises(SwapError,match='FORBIDDEN'):alice.rpc(Principal('other'),'resumeswap',{'swap_id':sid})
 assert snapshot(alice,sid)==before and not proposal_packets(alice)

def test_owner_resume_preserves_original_exhausted_budget(apps):
 params,mid,sid,before=fault(apps,total='10500');alice=apps[0]['alice'];clear_fault(alice)
 alice.rpc(Principal('operator',True),'resumeswap',{'swap_id':sid})
 assert snapshot(alice,sid)==before and before['budgets']==[['10500','0']]
 assert len(proposal_packets(alice))==1;finish(apps,sid)

@pytest.mark.parametrize('entry',['accept','resume'])
def test_expired_quote_not_extended_and_late_resume_cancels(apps,entry):
 params,mid,sid,before=fault(apps);nodes,time,ledgers,wire,deliver,step=apps;alice=nodes['alice'];clear_fault(alice);expiry=alice.journal.load(sid)[1]['quote']['quote']['expires_at'];time.n=expiry
 if entry=='accept':
  with pytest.raises(SwapError,match='QUOTE_EXPIRED'):alice.rpc(Principal('alice'),'acceptswapquote',params)
 else:assert alice.rpc(Principal('alice'),'resumeswap',{'swap_id':sid})['stage']=='proposed'
 assert snapshot(alice,sid)==before and not proposal_packets(alice)
 time.n=expiry+601;assert alice.rpc(Principal('alice'),'resumeswap',{'swap_id':sid})['stage']=='cancelled'
 assert alice.store.db.execute('SELECT held,used FROM mandates WHERE id=?',(mid,)).fetchone()==('0','0')
 assert not ledgers[A].records and not ledgers[B].records

@pytest.mark.parametrize('clock,code',[('long_mature','UNSAFE_TIMEOUT'),('short_late','LATE_REVEAL'),('stale','STALE_CHAIN')])
def test_original_deadlines_are_rechecked_not_regenerated(apps,monkeypatch,clock,code):
 params,mid,sid,before=fault(apps);nodes,time,ledgers,wire,deliver,step=apps;alice=nodes['alice'];clear_fault(alice);proposal=alice.journal.load(sid)[1]['proposal']
 if clock=='long_mature':ledgers[A].height=proposal['long_deadline']['value']
 elif clock=='short_late':ledgers[B].height=proposal['short_deadline']['value']-1
 else:
  original=alice.drivers[A].clock
  monkeypatch.setattr(alice.drivers[A],'clock',lambda:replace(original(),observed_at=time()-61))
 no_fresh_setup(alice,monkeypatch)
 with pytest.raises(SwapError,match=code):alice.rpc(Principal('alice'),'acceptswapquote',params)
 assert snapshot(alice,sid)==before and not proposal_packets(alice)

@pytest.mark.parametrize('conflict',['payload','stored_recipient','envelope_recipient'])
def test_conflicting_outbox_proposal_refuses(apps,conflict):
 params,mid,sid,before=fault(apps);alice=apps[0]['alice'];clear_fault(alice)
 alice.emit('bob','proposal',sid,alice.journal.load(sid)[1]['proposal']);packet=proposal_packets(alice)[0];packet_id=digest('BTX/SWAPNET/PACKET/2',packet);
 if conflict=='payload':packet['body']['payload']['nonce']='99'*32
 elif conflict=='envelope_recipient':packet['body']['recipient']='charlie'
 else:alice.store.db.execute("UPDATE sn_outbox SET recipient='charlie' WHERE id=?",(packet_id,))
 alice.store.db.execute('UPDATE sn_outbox SET body=? WHERE id=?',(dumps(packet),packet_id));queued=alice.store.db.execute('SELECT id FROM sn_outbox ORDER BY id').fetchall()
 with pytest.raises(SwapError,match='RECOVERY_CONFLICT'):alice.rpc(Principal('alice'),'acceptswapquote',params)
 assert snapshot(alice,sid)==before and alice.store.db.execute('SELECT id FROM sn_outbox ORDER BY id').fetchall()==queued

def test_enqueue_succeeded_but_caller_lost_reply_is_deduplicated(apps,monkeypatch):
 params,mid=prepare(apps);alice=apps[0]['alice'];original=alice.coordinator.emit
 def failed_reply(recipient,kind,*args):
  result=original(recipient,kind,*args)
  if kind=='proposal':raise SwapError('TEST_REPLY','Caller lost result after enqueue')
  return result
 monkeypatch.setattr(alice.coordinator,'emit',failed_reply)
 with pytest.raises(SwapError,match='TEST_REPLY'):alice.rpc(Principal('alice'),'acceptswapquote',params)
 sid=alice.store.db.execute('SELECT id FROM sn_negotiations').fetchone()[0];before=snapshot(alice,sid);packet=proposal_packets(alice);assert len(packet)==1
 alice=reopen_alice(apps);alice.rpc(Principal('alice'),'acceptswapquote',params)
 assert snapshot(alice,sid)==before and proposal_packets(alice)==packet
 finish(apps,sid)

def test_cancel_after_failed_retry_releases_once(apps):
 params,mid,sid,before=fault(apps);alice=apps[0]['alice']
 with pytest.raises(sqlite3.IntegrityError):alice.rpc(Principal('alice'),'acceptswapquote',params)
 clear_fault(alice)
 for _ in range(2):assert alice.rpc(Principal('alice'),'cancelswap',{'swap_id':sid})['stage']=='cancelled'
 assert alice.store.db.execute('SELECT held,used FROM mandates WHERE id=?',(mid,)).fetchone()==('0','0')
 assert alice.store.db.execute('SELECT id,state FROM reservations').fetchall()==[(before['reservation_ids'][0],'closed')]
 assert not proposal_packets(alice) and not apps[2][A].records and not apps[2][B].records
