"""Durable v2 execution journal. Network messages are never signing authority.

SQLite runs in WAL/FULL mode (via Store). Each externally visible operation is
persisted before sending; repeated messages and process restarts are idempotent.
Secrets and raw claim transactions are never returned by public read methods.
"""
from contextlib import nullcontext
from copy import deepcopy
from dataclasses import asdict
import hashlib
import json
import time
from .canonical import dumps, loads, hex32, digest, atoms, integer
from .errors import require, SwapError
from .store import apply_script

MIGRATION = '''
CREATE TABLE IF NOT EXISTS sn_settings(k TEXT PRIMARY KEY, body BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS sn_inbox(id TEXT PRIMARY KEY, expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS sn_inbox_broadcast(id TEXT PRIMARY KEY, sender TEXT NOT NULL, expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS sn_commit_receipts(
 id TEXT PRIMARY KEY REFERENCES sn_inbox(id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS sn_outbox(id TEXT PRIMARY KEY, recipient TEXT NOT NULL,
 command TEXT NOT NULL, body BLOB NOT NULL, next_try INTEGER NOT NULL,
 attempts INTEGER NOT NULL DEFAULT 0, acknowledged INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS sn_negotiations(id TEXT PRIMARY KEY, revision INTEGER NOT NULL,
 principal TEXT NOT NULL, peer TEXT NOT NULL, stage TEXT NOT NULL, body BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS sn_operations(id TEXT PRIMARY KEY, swap_id TEXT NOT NULL,
 asset TEXT NOT NULL, kind TEXT NOT NULL, txid TEXT NOT NULL, raw TEXT NOT NULL,
 state TEXT NOT NULL, metadata BLOB NOT NULL);
CREATE INDEX IF NOT EXISTS sn_ops_swap ON sn_operations(swap_id);
CREATE TABLE IF NOT EXISTS sn_observations(swap_id TEXT NOT NULL, leg TEXT NOT NULL,
 height INTEGER NOT NULL, blockhash TEXT NOT NULL, body BLOB NOT NULL,
 PRIMARY KEY(swap_id,leg));
CREATE TABLE IF NOT EXISTS sn_claimed_quotes(quote_id TEXT PRIMARY KEY, swap_id TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sn_nonces(asset TEXT NOT NULL,address TEXT NOT NULL,
 nonce INTEGER NOT NULL, operation TEXT NOT NULL UNIQUE, PRIMARY KEY(asset,address,nonce));
CREATE TABLE IF NOT EXISTS sn_grants(id TEXT PRIMARY KEY, principal TEXT NOT NULL,
 swap_id TEXT NOT NULL, body BLOB NOT NULL, reserved TEXT NOT NULL,
 consumed INTEGER NOT NULL DEFAULT 0, revoked INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS sn_sequences(identity TEXT PRIMARY KEY, n INTEGER NOT NULL);
'''


def local_dump(body):
    """Local records may contain larger raw data; wire canonical limits remain 64 KiB."""
    raw=json.dumps(body,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
    require(len(raw)<=4*1024*1024,'JOURNAL_LIMIT','Local record exceeds 4 MiB')
    return raw


def local_load(raw):
    require(len(raw)<=4*1024*1024,'JOURNAL_LIMIT','Local record exceeds 4 MiB')
    return json.loads(raw)


class Journal:
    def __init__(self,store):
        self.store=store
        with store.lock:
            version = store.db.execute('PRAGMA user_version').fetchone()[0]
            require(version in (0,2),
                    'SCHEMA_VERSION','Financial journal requires an explicitly supported migration')
            apply_script(store.db, MIGRATION)
            # Writing the same user_version again changes the schema cookie and
            # invalidates a SELECT that was already prepared.
            if version != 2:
                store.db.execute('PRAGMA user_version=2')
    def setting(self,key,default=None):
        with self.store.lock:
            r=self.store.db.execute('SELECT body FROM sn_settings WHERE k=?',(key,)).fetchone()
        return local_load(r[0]) if r else default
    def set_setting(self,key,value):
        with self.store.transaction() as db:
            db.execute('INSERT INTO sn_settings VALUES(?,?) ON CONFLICT(k) DO UPDATE SET body=excluded.body',(key,local_dump(value)))
    def next_sequence(self,identity):
        with self.store.transaction() as db:
            db.execute('INSERT INTO sn_sequences VALUES(?,1) ON CONFLICT(identity) DO UPDATE SET n=n+1',(identity,))
            return db.execute('SELECT n FROM sn_sequences WHERE identity=?',(identity,)).fetchone()[0]
    def seen(self,mid,expires,now,*,sender='',broadcast=False):
        """Return True for prior admission, not necessarily completed handling.

        A broadcast row can be dropped to keep room for a directed packet.
        Directed rows are not dropped to admit more broadcasts.
        """
        hex32(mid)
        sender=sender if type(sender) is str else ''
        if len(sender)>128:sender=sender[:128]
        with self.store.transaction() as db:
            db.execute('DELETE FROM sn_inbox WHERE expires<?',(now,))
            db.execute('DELETE FROM sn_inbox_broadcast WHERE id NOT IN (SELECT id FROM sn_inbox)')
            if db.execute('SELECT 1 FROM sn_inbox WHERE id=?',(mid,)).fetchone():return True
            if broadcast and sender:
                rows=db.execute('SELECT id FROM sn_inbox_broadcast WHERE sender=? ORDER BY expires',(sender,)).fetchall()
                if len(rows)>=32:
                    db.execute('DELETE FROM sn_inbox WHERE id=?',(rows[0][0],))
                    db.execute('DELETE FROM sn_inbox_broadcast WHERE id=?',(rows[0][0],))
            while db.execute('SELECT count(*) FROM sn_inbox').fetchone()[0]>=8192:
                old=db.execute('SELECT id FROM sn_inbox_broadcast ORDER BY expires LIMIT 1').fetchone()
                require(old is not None,'INBOX_LIMIT','Replay cache full')
                db.execute('DELETE FROM sn_inbox WHERE id=?',(old[0],))
                db.execute('DELETE FROM sn_inbox_broadcast WHERE id=?',(old[0],))
            db.execute('INSERT INTO sn_inbox VALUES(?,?)',(mid,expires))
            if broadcast:db.execute('INSERT INTO sn_inbox_broadcast VALUES(?,?,?)',(mid,sender,expires))
        return False
    def forget_message(self,mid):
        # A message whose processing raised before commit may be retried safely.
        with self.store.transaction() as db:
            db.execute('DELETE FROM sn_inbox WHERE id=?',(mid,))
            db.execute('DELETE FROM sn_inbox_broadcast WHERE id=?',(mid,))
    def commit_completed(self,mid):
        """Negotiation completion; retain the historical commit-named API/table."""
        hex32(mid)
        with self.store.lock:
            return self.store.db.execute('SELECT 1 FROM sn_commit_receipts WHERE id=?',(mid,)).fetchone() is not None
    def complete_commit(self,mid):
        """Persist successful handling before ACK, bounded by the admitted inbox."""
        hex32(mid)
        with self.store.transaction() as db:
            require(db.execute('SELECT 1 FROM sn_inbox WHERE id=?',(mid,)).fetchone() is not None,
                    'INBOX_MISSING','Negotiation completion requires inbox admission')
            db.execute('INSERT OR IGNORE INTO sn_commit_receipts VALUES(?)',(mid,))
    def enqueue(self,recipient,command,packet,now):
        mid=digest('BTX/SWAPNET/PACKET/2',packet)
        with self.store.transaction() as db:
            require(db.execute('SELECT count(*) FROM sn_outbox WHERE acknowledged=0').fetchone()[0]<2048,'OUTBOX_LIMIT','Outbox full')
            db.execute('INSERT OR IGNORE INTO sn_outbox VALUES(?,?,?,?,?,0,0)',(mid,recipient,command,dumps(packet),now))
        return mid
    def due(self,now,limit=32):
        with self.store.lock:
            rows=self.store.db.execute('SELECT id,recipient,command,body,attempts FROM sn_outbox WHERE acknowledged=0 AND next_try<=? ORDER BY next_try LIMIT ?',(now,limit)).fetchall()
        return [(r[0],r[1],r[2],loads(r[3]),r[4]) for r in rows]
    def has_proposal(self,sid,recipient,proposal,now):
        """An exact queued proposal, including acknowledged/not-due rows."""
        hex32(sid);found=False
        with self.store.lock:
            rows=self.store.db.execute("SELECT recipient,body FROM sn_outbox WHERE command='swterms'")
            for queued_recipient,raw in rows:
                body=loads(raw)['body']
                if body['kind']!='proposal' or body['swap_id']!=sid:continue
                require(queued_recipient==recipient and body['recipient']==recipient and body['payload']==proposal,
                        'RECOVERY_CONFLICT','Queued proposal differs from saved intent')
                if body['expires_at']>now:found=True
        return found
    def sent(self,mid,now):
        with self.store.transaction() as db:
            row=db.execute('SELECT attempts FROM sn_outbox WHERE id=?',(mid,)).fetchone()
            if row:db.execute('UPDATE sn_outbox SET attempts=attempts+1,next_try=? WHERE id=?',(now+min(60,2**min(row[0]+1,6)),mid))
    def ack(self,mid,recipient):
        with self.store.transaction() as db:
            db.execute('UPDATE sn_outbox SET acknowledged=1 WHERE id=? AND recipient=?',(hex32(mid),recipient))
    def compact_outbox(self,now):
        with self.store.transaction() as db:
            db.execute('DELETE FROM sn_outbox WHERE acknowledged=1 AND next_try<?',(now-3600,))
            # Negotiation messages have expiry; sessions themselves remain durable.
            rows=db.execute('SELECT id,body FROM sn_outbox WHERE acknowledged=0').fetchall()
            for mid,body in rows:
                if loads(body)['body']['expires_at']<now:db.execute('DELETE FROM sn_outbox WHERE id=?',(mid,))
    def ensure_capacity(self):
        with self.store.lock:
            # Junk proposals that never signed an operation must not fill the
            # journal. Complete and refunded sessions stay counted and are not deleted.
            counted=self.store.db.execute(
                "SELECT count(*) FROM sn_negotiations AS n WHERE NOT ("
                "n.stage IN ('cancelled','rejected') AND NOT EXISTS ("
                "SELECT 1 FROM sn_operations AS o WHERE o.swap_id=n.id))").fetchone()[0]
            require(counted<4096,
                    'SESSION_LIMIT','Journal session capacity reached; preserve recovery state before offline archival')
            require(self.store.db.execute("SELECT count(*) FROM sn_negotiations WHERE stage NOT IN ('complete','refunded','cancelled','rejected')").fetchone()[0]<128,
                    'ACTIVE_LIMIT','At most 128 active settlements per native node')
    def save(self,sid,body,expected=-1,*,db=None):
        hex32(sid)
        with (self.store.transaction() if db is None else nullcontext(db)) as db:
            old=db.execute('SELECT revision,body FROM sn_negotiations WHERE id=?',(sid,)).fetchone()
            require((old[0] if old else -1)==expected,'REVISION_CONFLICT','Concurrent swap update')
            if old:
                previous=local_load(old[1])
                require(not previous.get('secret_exposed') or body.get('secret_exposed') is True,'SECRET_ROLLBACK','Secret exposure cannot be undone')
                require(previous['principal']==body['principal'] and previous['peer']==body['peer'],'SESSION_BINDING','Immutable session owner changed')
                if previous.get('agreement_id'):
                    require(previous['agreement_id']==body.get('agreement_id'),'AGREEMENT_CHANGED','Accepted agreement is immutable')
            if old:
                # Decisions still use fresh driver observations on every tick.
                # Every unchanged stage, including committed, skips a write when
                # only updated_at and observation observed_at moved.
                snapshots = (deepcopy(previous), deepcopy(body))
                for snapshot in snapshots:
                    snapshot.pop('updated_at', None)
                    for observation in snapshot.get('observations', {}).values():
                        observation.pop('observed_at', None)
                if snapshots[0] == snapshots[1]:
                    return old[0]
            if not old:self.ensure_capacity()
            rev=expected+1
            db.execute('INSERT INTO sn_negotiations VALUES(?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET revision=excluded.revision,stage=excluded.stage,body=excluded.body',
                       (sid,rev,body['principal'],body['peer'],body['stage'],local_dump(body)))
            self.store._audit(db,{'type':'swap_v2_saved','id':sid,'revision':rev,'stage':body['stage']})
        return rev
    def close_unfunded_terminal(self, sid, body, expected):
        """Atomically close an unfunded session, including old partial closeouts."""
        require(body['stage'] in {'cancelled','rejected'}, 'SESSION_STATE', 'Expected unfunded terminal state')
        with self.store.transaction() as db:
            current = db.execute('SELECT revision,body FROM sn_negotiations WHERE id=?', (sid,)).fetchone()
            require(current and current[0] == expected, 'REVISION_CONFLICT', 'Concurrent swap update')
            state = local_load(current[1])
            rid = state.get('reservation_id')
            require(body.get('reservation_id') == rid, 'RECOVERY_CONFLICT', 'Reservation changed')
            require(not any(state.get(k) for k in ('funding_prepared','funding_broadcast',
                    'recovery_ready','secret_exposed','fund_op','refund_op','evm_refund_plan')),
                    'FUNDS_LOCKED', 'Prepared/funded swaps require refund recovery')
            own = 'a' if state['role'] == 'initiator' else 'b'
            require(not state.get('refs', {}).get(own), 'FUNDS_LOCKED', 'Local funding reference requires recovery')
            require(not db.execute('SELECT 1 FROM sn_operations WHERE swap_id=?', (sid,)).fetchone(),
                    'FUNDS_LOCKED', 'Durable operations require recovery')
            if rid:
                require(not db.execute('SELECT 1 FROM coinlocks WHERE reservation_id=?', (rid,)).fetchone(),
                        'FUNDS_LOCKED', 'Reserved inputs require recovery')
            grants = db.execute('SELECT id,principal,body,consumed FROM sn_grants WHERE swap_id=?', (sid,)).fetchall()
            for gid, principal, raw, consumed in grants:
                grant = local_load(raw)
                require(not consumed, 'FUNDS_LOCKED', 'Consumed funding grant requires recovery')
                require(principal == state['principal'] and grant['principal'] == principal
                        and grant['swap_id'] == sid and grant['reservation_id'] == rid,
                        'RECOVERY_CONFLICT', 'Signing grant does not match session reservation')
            require(not state.get('grant_id') or any(g[0] == state['grant_id'] for g in grants),
                    'RECOVERY_CONFLICT', 'Saved signing grant missing')
            if rid:
                reservation = db.execute('SELECT principal,state FROM reservations WHERE id=?', (rid,)).fetchone()
                require(reservation and reservation[0] == state['principal'],
                        'RECOVERY_CONFLICT', 'Reservation does not match session owner')
                require(reservation[1] in {'held','closed'}, 'FUNDS_LOCKED', 'Funded reservation requires recovery')
                if reservation[1] == 'held':
                    self.store._settle_reservation(db, rid, 0)
                # Old code could commit release but fail the session write.
                # Complete only the terminal state without touching mandate
                # counters again or weakening global settlement guards.
            db.execute('UPDATE sn_grants SET revoked=1 WHERE swap_id=?', (sid,))
            return self.save(sid, body, expected, db=db)

    def close_unfunded_responder(self, sid, body, expected):
        """Release an unfunded responder after the caller verifies the remote refund."""
        rid = body["reservation_id"]
        with self.store.transaction() as db:
            current = db.execute(
                "SELECT revision,body FROM sn_negotiations WHERE id=?", (sid,)
            ).fetchone()
            require(current and current[0] == expected, "REVISION_CONFLICT", "Concurrent swap update")
            state = local_load(current[1])
            if state["role"] != "responder" or state["stage"] != "committed":
                return False
            if (state["secret_exposed"] or state["funding_prepared"] or state["funding_broadcast"]
                    or state["recovery_ready"] or state.get("fund_op") or state["refs"].get("b")):
                return False
            if db.execute("SELECT 1 FROM sn_operations WHERE swap_id=?", (sid,)).fetchone():
                return False
            if db.execute("SELECT 1 FROM coinlocks WHERE reservation_id=?", (rid,)).fetchone():
                return False
            grant = db.execute(
                "SELECT consumed,body FROM sn_grants WHERE id=? AND swap_id=?",
                (state["grant_id"], sid),
            ).fetchone()
            if not grant or grant[0] or local_load(grant[1])["reservation_id"] != rid:
                return False
            reservation = db.execute("SELECT state FROM reservations WHERE id=?", (rid,)).fetchone()
            if reservation != ("held",):
                return False
            self.store._settle_reservation(db, rid, 0)
            db.execute("UPDATE sn_grants SET revoked=1 WHERE id=?", (state["grant_id"],))
            closed = {**body, "stage": "cancelled", "last_action": "counterparty_refunded_unfunded"}
            db.execute("UPDATE sn_negotiations SET revision=?,stage=?,body=? WHERE id=?",
                       (expected+1, closed["stage"], local_dump(closed), sid))
            self.store._audit(db, {"type":"swap_v2_saved", "id":sid, "revision":expected+1,
                                   "stage":closed["stage"]})
            return True

    def load(self,sid):
        hex32(sid)
        with self.store.lock:r=self.store.db.execute('SELECT revision,body FROM sn_negotiations WHERE id=?',(sid,)).fetchone()
        require(r is not None,'NOT_FOUND','Swap not found')
        return r[0],local_load(r[1])
    def scheduled(self, *, terminal, after='', limit=4):
        """Bounded keyset rotation over eligible rows, not a display/history page."""
        integer(limit,lo=1,hi=4)
        stages = "stage IN ('complete','refunded')" if terminal else "stage NOT IN ('complete','refunded','cancelled','rejected')"
        with self.store.lock:
            rows=self.store.db.execute('SELECT id,revision,body FROM sn_negotiations WHERE '+stages+' AND id>? ORDER BY id LIMIT ?', (after,limit)).fetchall()
            if after and len(rows)<limit:
                rows+=self.store.db.execute('SELECT id,revision,body FROM sn_negotiations WHERE '+stages+' AND id<=? ORDER BY id LIMIT ?', (after,limit-len(rows))).fetchall()
        return [(r[0],r[1],local_load(r[2])) for r in rows]
    def active_asset_in_use(self, asset):
        # Reorgs can reopen terminal rows beyond the new-session active cap.
        # Stream all active agreements; do not apply a display/session limit.
        with self.store.lock:
            rows=self.store.db.execute("SELECT body FROM sn_negotiations WHERE stage NOT IN ('complete','refunded','cancelled','rejected')")
            while True:
                batch=rows.fetchmany(64)
                if not batch:return False
                for (raw,) in batch:
                    agreement=local_load(raw).get('agreement',{})
                    if asset in (agreement.get('long_leg',{}).get('asset'),agreement.get('short_leg',{}).get('asset')):return True
    def owned_session_ids(self, principal, ids):
        # Callers supply only IDs referenced by one bounded audit page.
        ids=tuple({sid for sid in ids if type(sid) is str})
        require(len(ids)<=500,'EVENT_LIMIT','Too many event session references')
        if not ids:return set()
        with self.store.lock:
            rows=self.store.db.execute('SELECT id FROM sn_negotiations WHERE principal=? AND id IN ('+','.join('?' for _ in ids)+')',(principal,*ids)).fetchall()
        return {r[0] for r in rows}
    def all(self,principal=None,limit=512):
        integer(limit,lo=1,hi=4096)
        with self.store.lock:
            if principal is None:rows=self.store.db.execute('SELECT id,revision,body FROM sn_negotiations ORDER BY id LIMIT ?',(limit,)).fetchall()
            else:rows=self.store.db.execute('SELECT id,revision,body FROM sn_negotiations WHERE principal=? ORDER BY id LIMIT ?',(principal,limit)).fetchall()
        return [(r[0],r[1],local_load(r[2])) for r in rows]
    def claim_quote(self,qid,sid,*,db=None):
        with (self.store.transaction() if db is None else nullcontext(db)) as db:
            row=db.execute('SELECT swap_id FROM sn_claimed_quotes WHERE quote_id=?',(qid,)).fetchone()
            require(not row or row[0]==sid,'QUOTE_ALREADY_ACCEPTED','Quote belongs to another swap')
            db.execute('INSERT OR IGNORE INTO sn_claimed_quotes VALUES(?,?)',(qid,sid))
    def prepare(self,sid,asset,kind,txid,raw,metadata=None,*,db=None):
        require(kind in {'fund','refund','claim','withdraw','approve','bump'},'OPERATION','Unknown operation')
        hex32(txid.removeprefix('0x'))
        require(type(raw) is str and 0<len(raw)<=4_000_000,'RAW_TX','Invalid signed transaction')
        try:bytes.fromhex(raw.removeprefix('0x'))
        except ValueError as e:raise SwapError('RAW_TX','Malformed signed transaction') from e
        oid=digest('BTX/SWAPNET/OPERATION/2',{'swap_id':sid,'asset':asset,'kind':kind,'txid':txid})
        with (self.store.transaction() if db is None else nullcontext(db)) as db:
            row=db.execute('SELECT raw FROM sn_operations WHERE id=?',(oid,)).fetchone()
            require(not row or row[0]==raw,'OPERATION_CHANGED','Immutable signed bytes changed')
            db.execute('INSERT OR IGNORE INTO sn_operations VALUES(?,?,?,?,?,?,\'prepared\',?)',(oid,sid,asset,kind,txid,raw,local_dump(metadata or {})))
            self.store._audit(db,{'type':'operation_v2_prepared','id':oid,'swap_id':sid,'kind':kind,'txid':txid})
        return oid
    def operations(self,sid,private=False):
        with self.store.lock:rows=self.store.db.execute('SELECT id,asset,kind,txid,raw,state,metadata FROM sn_operations WHERE swap_id=? ORDER BY rowid',(sid,)).fetchall()
        out=[]
        for r in rows:
            item=dict(zip(('id','asset','kind','txid','raw','state','metadata'),r));item['metadata']=local_load(item['metadata'])
            if not private:item.pop('raw');item['metadata']={k:v for k,v in item['metadata'].items() if k in {'fee_atoms','replacement_of','nonce'}}
            out.append(item)
        return out
    def operation(self,oid):
        with self.store.lock:r=self.store.db.execute('SELECT id,asset,kind,txid,raw,state,metadata FROM sn_operations WHERE id=?',(oid,)).fetchone()
        require(r is not None,'NOT_FOUND','Prepared transaction missing')
        d=dict(zip(('id','asset','kind','txid','raw','state','metadata'),r));d['metadata']=local_load(d['metadata']);return d
    def broadcast(self,oid,driver):
        op=self.operation(oid)
        # Reconcile first after an ambiguous network failure or process death.
        if driver.has_transaction(op['txid']):result=op['txid']
        else:result=driver.broadcast(op['raw'])
        require(result==op['txid'],'TXID_MISMATCH','Broadcast returned a different transaction id')
        with self.store.transaction() as db:
            db.execute("UPDATE sn_operations SET state='broadcast' WHERE id=?",(oid,))
            self.store._audit(db,{'type':'operation_v2_broadcast','id':oid,'txid':result})
        return result
    def reserve_nonce(self,asset,address,operation,pending_nonce,*,db=None):
        integer(pending_nonce)
        with (self.store.transaction() if db is None else nullcontext(db)) as db:
            row=db.execute('SELECT nonce FROM sn_nonces WHERE operation=?',(operation,)).fetchone()
            if row:return row[0]
            row=db.execute('SELECT max(nonce) FROM sn_nonces WHERE asset=? AND address=?',(asset,address)).fetchone()
            last=None if row[0] is None else row[0]
            # Do not allocate past a nonce this process still holds. A dropped
            # transaction would otherwise leave every later nonce stuck.
            if last is not None and pending_nonce<=last:
                raise SwapError('NONCE_HELD','An earlier local EVM nonce is still reserved; replace that transaction instead of allocating past it')
            db.execute('INSERT INTO sn_nonces VALUES(?,?,?,?)',(asset,address,pending_nonce,operation))
            return pending_nonce
    def checkpoint(self):
        with self.store.lock:self.store.db.execute('PRAGMA wal_checkpoint(FULL)')
