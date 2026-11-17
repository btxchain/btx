"""Bounded valid-message durability probe. Actual child exit; simulated ledgers/signers."""
import os,json,hashlib,multiprocessing,sqlite3
from swapnet.journal import Journal
from swapnet.canonical import dumps
from pathlib import Path
from dataclasses import asdict
import pytest
from test_runtime_recovery_v2 import apps
from test_execution_v2 import A,B,NETWORK,Driver
from swapnet.application import Application
from swapnet.authorization import Principal
from swapnet.store import Store
from swapnet.vault import ForeignKeyVault
from swapnet.canonical import loads,digest
from swapnet.policy import Mandate
from swapnet.errors import SwapError

def packet_kind(item):
 try:return loads(item[2])['packet']['body']['kind']
 except (KeyError,TypeError):return None

def commit_boundary(apps,mandate_lifetime=10000):
 nodes,time,ledgers,wire,deliver,step=apps;mids={}
 for n,asset in [('alice',A),('bob',B)]:
  m=Mandate(n,asset,'10000000','100000','1000',time()+mandate_lifetime,'66'*32)
  mids[n]=nodes[n].rpc(Principal(n,True),'createswapmandate',{'mandate':asdict(m)})['mandate_id']
 market={'sell_asset':A,'buy_asset':B,'numerator':'2','denominator':'1','maker_fee_atoms':'10','max_receive_network_fee_atoms':'100','max_input_atoms':'100000','expires_at':time()+10000}
 nodes['bob'].rpc(Principal('bob',True),'setswapmarket',{'market':market,'mandate_id':mids['bob'],'max_local_fee_atoms':'500','refund_fee_atoms':'100','claim_fee_atoms':'100'})
 deliver();rfq=nodes['alice'].rpc(Principal('alice'),'requestswapquote',{'sell_asset':A,'buy_asset':B,'sell_atoms':'10000'})
 for _ in range(4):step()
 quotes=nodes['alice'].rpc(Principal('alice'),'getswapquotes',{'request_id':rfq['request_id']})['quotes'];assert quotes
 sid=nodes['alice'].rpc(Principal('alice'),'acceptswapquote',{'quote_id':quotes[0]['id'],'mandate_id':mids['alice'],'max_local_fee_atoms':'500','refund_fee_atoms':'100'})['swap_id']
 for _ in range(12):
  while wire:
   item=wire.pop(0)
   if packet_kind(item)=='commit':
    sender,command,raw=item;assert sender=='alice'
    assert nodes['bob'].journal.load(sid)[1]['stage']=='offered'
    packet=loads(raw)['packet'];mid=digest('BTX/SWAPNET/PACKET/2',packet)
    assert nodes['alice'].store.db.execute('SELECT acknowledged FROM sn_outbox WHERE id=?',(mid,)).fetchone()==(0,)
    return sid,command,raw,mid
   sender,command,raw=item;nodes['bob' if sender=='alice' else 'alice'].on_message(1,command,raw)
  for app in nodes.values():app.tick()
 raise AssertionError('Did not reach valid signed commit')

def reopened(old,ledgers,time,wire):
 return Application(Store(Path(old.vault.path).parent/'state.sqlite'),NETWORK,old.identity,ForeignKeyVault(old.vault.path,b'1'*32),{a:Driver(l,'bob') for a,l in ledgers.items()},lambda peer,command,raw:(wire.append(('bob',command,raw)) or True),clock=time,policy=old.coordinator.policy)

def settle(apps,sid):
 nodes,time,ledgers,wire,deliver,step=apps
 for _ in range(40):step()
 assert all(n.journal.load(sid)[1]['stage']=='complete' for n in nodes.values())
 assert len(ledgers[A].records)==len(ledgers[B].records)==1

def counts(app,sid):
 db=app.store.db
 return (db.execute('SELECT count(*) FROM sn_grants WHERE swap_id=?',(sid,)).fetchone()[0],
         db.execute('SELECT count(*) FROM reservations').fetchone()[0],
         tuple(db.execute('SELECT held,used FROM mandates ORDER BY id').fetchall()),
         tuple(db.execute('SELECT id FROM sn_grants WHERE swap_id=? ORDER BY id',(sid,)).fetchall()),
         tuple(db.execute('SELECT id FROM reservations ORDER BY id').fetchall()))

def has_ack(app,mid):
 return any(loads(raw)['body'].get('kind')=='ack' and loads(raw)['body']['payload'].get('message_id')==mid
            for raw, in app.store.db.execute('SELECT body FROM sn_outbox'))

def legacy_row(app,mid,raw):
 # Old binaries know only the two-column admission table, not completion.
 app.store.db.execute('DROP TABLE IF EXISTS sn_commit_receipts')
 app.store.db.execute('INSERT OR IGNORE INTO sn_inbox VALUES(?,?)',(mid,loads(raw)['packet']['body']['expires_at']))
 app.journal=Journal(app.store)

def crash_reopen(apps,sid,command,raw,cut):
 nodes,time,ledgers,wire,deliver,step=apps;old=nodes['bob'];old.close()
 def child_run():
  bob=reopened(old,ledgers,time,wire);bob.peer_connected(1)
  if cut=='admission':
   orig=bob.journal.seen
   def seen(*args):
    duplicate=orig(*args);assert not duplicate;os._exit(73)
   bob.journal.seen=seen
  elif cut in {'grant','session'}:
   orig=bob.coordinator._save
   def save(*args):
    if cut=='grant':
     assert bob.store.db.execute('SELECT count(*) FROM sn_grants WHERE swap_id=?',(sid,)).fetchone()[0]==1
     os._exit(73)
    rev=orig(*args);assert bob.journal.load(sid)[1]['stage']=='committed';os._exit(73)
   bob.coordinator._save=save
  else:
   orig=bob.emit
   def emit(recipient,kind,*args):
    if kind=='ack':os._exit(73)
    return orig(recipient,kind,*args)
   bob.emit=emit
  bob.on_message(1,command,raw);os._exit(74)
 child=multiprocessing.get_context('fork').Process(target=child_run);child.start();child.join(10)
 if child.is_alive():child.kill();child.join();pytest.fail('Child exceeded bounded restart window')
 assert child.exitcode==73
 nodes['bob']=bob=reopened(old,ledgers,time,wire);bob.peer_connected(1)
 return bob

@pytest.mark.skipif(os.name=='nt',reason='Requires fork for the deliberate abrupt process exit')
@pytest.mark.parametrize('cut',['admission','grant','session','before_ack'])
def test_commit_replay_after_actual_exit(apps,cut):
 nodes,time,ledgers,wire,deliver,step=apps;sid,command,raw,mid=commit_boundary(apps)
 bob=crash_reopen(apps,sid,command,raw,cut);before=counts(bob,sid);original=bob._process
 if cut=='before_ack':
  def duplicate_effect(_):pytest.fail('Completed duplicate reran handler after reopen')
  bob._process=duplicate_effect
 bob.on_message(1,command,raw)
 assert bob.journal.load(sid)[1]['stage']=='committed','Valid replay was ACKed without applying the commit'
 assert has_ack(bob,mid)
 assert counts(bob,sid)[0:2]==(1,1)
 assert counts(bob,sid)[2]==before[2]
 assert counts(bob,sid)[4]==before[4]
 if before[0]:assert counts(bob,sid)[3]==before[3]
 bob._process=original
 settle(apps,sid)
 assert nodes['alice'].store.db.execute('SELECT acknowledged FROM sn_outbox WHERE id=?',(mid,)).fetchone()==(1,)

@pytest.mark.parametrize('already_applied',[False,True])
def test_legacy_seen_only_revalidated_once(apps,already_applied):
 nodes,time,ledgers,wire,deliver,step=apps;sid,command,raw,mid=commit_boundary(apps);bob=nodes['bob']
 if already_applied:bob.on_message(1,command,raw)
 before=counts(bob,sid);legacy_row(bob,mid,raw);old=bob;old.close();nodes['bob']=bob=reopened(old,ledgers,time,wire);bob.peer_connected(1)
 processed=[];original=bob._process
 def record(b):processed.append(b['kind']);return original(b)
 bob._process=record;bob.on_message(1,command,raw)
 assert bob.journal.load(sid)[1]['stage']=='committed','Legacy admission masked unapplied commit'
 assert processed==['commit'],'Legacy seen-only completion must be verified, not backfilled'
 assert counts(bob,sid)[0:2]==(1,1) and counts(bob,sid)[2]==before[2]
 assert counts(bob,sid)[4]==before[4]
 if already_applied:assert counts(bob,sid)[3]==before[3]
 bob.on_message(1,command,raw);assert processed==['commit']
 settle(apps,sid)

def test_caught_handler_error_retries(apps):
 nodes,time,ledgers,wire,deliver,step=apps;sid,command,raw,mid=commit_boundary(apps);bob=nodes['bob'];original=bob._process
 def transient(_):raise SwapError('TEST_TRANSIENT','Controlled pre-handler refusal')
 bob._process=transient
 with pytest.raises(SwapError,match='TEST_TRANSIENT'):bob.on_message(1,command,raw)
 assert not has_ack(bob,mid)
 assert bob.store.db.execute('SELECT count(*) FROM sn_inbox WHERE id=?',(mid,)).fetchone()==(0,)
 bob._process=original;bob.on_message(1,command,raw);settle(apps,sid)

def test_completion_store_error_withholds_ack_and_retries(apps):
 nodes,time,ledgers,wire,deliver,step=apps;sid,command,raw,mid=commit_boundary(apps);bob=nodes['bob']
 bob.store.db.execute("CREATE TRIGGER refuse_receipt BEFORE INSERT ON sn_commit_receipts BEGIN SELECT RAISE(ABORT,'receipt fault'); END")
 with pytest.raises(sqlite3.IntegrityError,match='receipt fault'):bob.on_message(1,command,raw)
 assert bob.journal.load(sid)[1]['stage']=='committed'
 assert not has_ack(bob,mid) and not bob.journal.commit_completed(mid)
 before=counts(bob,sid);bob.store.db.execute('DROP TRIGGER refuse_receipt');bob.on_message(1,command,raw)
 assert counts(bob,sid)==before and bob.journal.commit_completed(mid)
 settle(apps,sid)

def test_ack_enqueue_error_keeps_completion(apps):
 nodes,time,ledgers,wire,deliver,step=apps;sid,command,raw,mid=commit_boundary(apps);bob=nodes['bob'];original=bob.emit
 def refused(recipient,kind,*args):
  if kind=='ack':raise SwapError('TEST_ACK','Controlled ACK enqueue error')
  return original(recipient,kind,*args)
 bob.emit=refused
 with pytest.raises(SwapError,match='TEST_ACK'):bob.on_message(1,command,raw)
 assert bob.journal.commit_completed(mid) and not has_ack(bob,mid);before=counts(bob,sid)
 bob.emit=original
 def forbidden(_):pytest.fail('ACK retry reapplied completed commit')
 bob._process=forbidden;bob.on_message(1,command,raw);assert counts(bob,sid)==before and has_ack(bob,mid)
 # Restore ordinary handler for later funded packets.
 bob._process=Application._process.__get__(bob,Application);settle(apps,sid)

@pytest.mark.parametrize('invalid',['signature','network','expired','agreement','sender'])
def test_completed_receipt_does_not_bypass_validation(apps,invalid):
 from test_execution_v2 import Identity
 nodes,time,ledgers,wire,deliver,step=apps;sid,command,raw,mid=commit_boundary(apps);bob=nodes['bob'];bob.on_message(1,command,raw);before=counts(bob,sid)
 packet=loads(raw);body=packet['packet']['body']
 if invalid=='signature':packet['packet']['signature']='00'*64
 elif invalid=='network':body['network']='99'*32
 elif invalid=='expired':time.n=body['expires_at']
 elif invalid=='agreement':body['payload']['agreement_id']='99'*32
 elif invalid=='sender':body['sender']='mallory'
 if invalid in {'agreement','sender'}:
  identity=nodes['alice'].identity if invalid=='agreement' else Identity('mallory')
  packet['packet']['signature']=identity.sign('BTX/SWAPNET/ENVELOPE/2:'+digest('BTX/SWAPNET/ENVELOPE/2',body))
 newmid=digest('BTX/SWAPNET/PACKET/2',packet['packet'])
 with pytest.raises(SwapError):bob.on_message(1,command,dumps(packet))
 assert counts(bob,sid)==before
 if newmid!=mid:assert not bob.journal.commit_completed(newmid)
 assert len(ledgers[B].records)==0

@pytest.mark.parametrize('state',['revoked','expired','cancelled','rejected'])
def test_pending_legacy_commit_preserves_refusals(apps,state):
 nodes,time,ledgers,wire,deliver,step=apps;sid,command,raw,mid=commit_boundary(apps,mandate_lifetime=10 if state=='expired' else 10000);bob=nodes['bob'];legacy_row(bob,mid,raw)
 s=bob.journal.load(sid)[1];mandate=bob.store.db.execute('SELECT mandate_id FROM reservations WHERE id=?',(s['reservation_id'],)).fetchone()[0]
 if state=='revoked':bob.authority.revoke(Principal('bob',True),mandate)
 elif state=='expired':time.n+=11
 elif state=='cancelled':bob.coordinator.cancel(Principal('bob'),sid)
 else:bob.coordinator.receive_decline('alice',sid,{'code':'TEST_DECLINE','message':'Legitimate decline'})
 before=counts(bob,sid)
 with pytest.raises(SwapError):bob.on_message(1,command,raw)
 assert not has_ack(bob,mid) and counts(bob,sid)==before and not bob.journal.commit_completed(mid)
 assert not ledgers[B].records

def test_receipts_share_capacity_and_expiry(apps):
 alice=apps[0]['alice'];j=alice.journal;now=alice.now();mid='88'*32
 assert alice.store.db.execute('PRAGMA foreign_keys').fetchone()==(1,)
 with alice.store.transaction() as db:db.executemany('INSERT INTO sn_inbox VALUES(?,?)',[(format(i,'064x'),now+10) for i in range(8192)])
 with pytest.raises(SwapError,match='INBOX_LIMIT'):j.seen(mid,now+10,now)
 existing=format(1,'064x');assert j.seen(existing,now+10,now);j.complete_commit(existing);assert j.commit_completed(existing)
 with pytest.raises(SwapError,match='INBOX_MISSING'):j.complete_commit(mid)
 assert not j.seen(mid,now+20,now+11)
 assert not j.commit_completed(existing)
 assert alice.store.db.execute('SELECT count(*) FROM sn_commit_receipts').fetchone()==(0,)
 j.complete_commit(mid);j.forget_message(mid);assert not j.commit_completed(mid)
 assert alice.store.db.execute('PRAGMA foreign_key_check').fetchall()==[]

def test_original_refund_after_recovered_commit(apps):
 nodes,time,ledgers,wire,deliver,step=apps;sid,command,raw,mid=commit_boundary(apps);bob=nodes['bob'];legacy_row(bob,mid,raw);bob.on_message(1,command,raw)
 assert bob.journal.load(sid)[1]['stage']=='committed'
 # Deliberately withhold the maker: only the original initiator is scheduled.
 alice=nodes['alice']
 for _ in range(6):alice.coordinator.tick();ledgers[A].mine();ledgers[B].mine();time.n+=1
 s=alice.journal.load(sid)[1];txid=s['refs']['a']['txid'];fund=ledgers[A].transactions[txid];op=s['refund_op'];refund=alice.store.db.execute('SELECT txid,raw FROM sn_operations WHERE id=?',(op,)).fetchone();maturity=s['agreement']['long_leg']['lock_value']
 ledgers[A].height=maturity-1
 with pytest.raises(SwapError,match='REFUND_EARLY'):alice.coordinator.request_refund(Principal('alice'),sid)
 alice.coordinator.tick_one(sid);assert ledgers[A].records[txid]['state']=='locked'
 ledgers[A].height=maturity;alice.coordinator.request_refund(Principal('alice'),sid);assert ledgers[A].records[txid]['state']=='refunded'
 ledgers[A].mine(3);alice.coordinator.tick_one(sid);assert alice.journal.load(sid)[1]['stage']=='refunded'
 assert ledgers[A].transactions[txid]==fund and len(ledgers[A].records)==1 and not ledgers[B].records
 assert alice.store.db.execute('SELECT txid,raw FROM sn_operations WHERE id=?',(op,)).fetchone()==refund
 assert not alice.journal.load(sid)[1]['secret_exposed']
