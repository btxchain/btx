"""Crash-consistent reservations, mandates, immutable operations and audit events.

No network I/O occurs inside SQL transactions. Serialized raw transactions are
persisted BEFORE broadcast. Retrying an ambiguous broadcast reuses the same bytes.
"""
from contextlib import contextmanager, nullcontext
from dataclasses import asdict
import hashlib
import os
from pathlib import Path
import sqlite3
import threading
from .canonical import dumps, loads, atoms, digest, hex32, integer
from .errors import require, SwapError
from .policy import Mandate
from .quote import Quote

SCHEMA = """
CREATE TABLE IF NOT EXISTS metadata(k TEXT PRIMARY KEY,v TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS mandates(id TEXT PRIMARY KEY,body BLOB NOT NULL,held TEXT NOT NULL,used TEXT NOT NULL,revoked INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS reservations(id TEXT PRIMARY KEY,quote_id TEXT UNIQUE NOT NULL,mandate_id TEXT NOT NULL,principal TEXT NOT NULL,cost TEXT NOT NULL,state TEXT NOT NULL,body BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS coinlocks(chain TEXT NOT NULL,outpoint TEXT NOT NULL,reservation_id TEXT NOT NULL,PRIMARY KEY(chain,outpoint));
CREATE TABLE IF NOT EXISTS sessions(id TEXT PRIMARY KEY,revision INTEGER NOT NULL,body BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS operations(id TEXT PRIMARY KEY,chain TEXT NOT NULL,kind TEXT NOT NULL,txid TEXT NOT NULL,raw TEXT NOT NULL,state TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS peer_sequences(identity TEXT PRIMARY KEY,sequence INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS providers(identity TEXT PRIMARY KEY,expires INTEGER NOT NULL,body BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS audit(seq INTEGER PRIMARY KEY AUTOINCREMENT,prev TEXT NOT NULL,digest TEXT NOT NULL,body BLOB NOT NULL);
"""

class Store:
    def __init__(self, path):
        path = Path(path)
        require(not path.is_symlink(), "DATABASE_PATH", "Database cannot be a symlink")
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if os.name != "nt":
            st = path.parent.stat()
            require(st.st_uid == os.getuid() and not st.st_mode & 0o077,
                    "DIRECTORY_PERMISSIONS", "SwapNet data directory must be private (0700)")
        fd = os.open(path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
        os.close(fd)
        if os.name != "nt":
            require(not path.stat().st_mode & 0o077, "DATABASE_PERMISSIONS", "Database must be private (0600)")
        self.lock = threading.RLock()
        self.db = sqlite3.connect(path, timeout=5, isolation_level=None, check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.executescript(SCHEMA)
        row = self.db.execute("SELECT v FROM metadata WHERE k='schema'").fetchone()
        require(row is None or row[0] == '1', "SCHEMA_VERSION", "Database needs an explicit migration")
        self.db.execute("INSERT OR IGNORE INTO metadata VALUES('schema','1')")
        self.verify_audit()

    def close(self):
        with self.lock:
            self.db.execute("PRAGMA wal_checkpoint(FULL)")
            self.db.close()

    @contextmanager
    def transaction(self):
        with self.lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                yield self.db
                self.db.execute("COMMIT")
            except BaseException:
                self.db.execute("ROLLBACK")
                raise

    def _audit(self, db, event):
        raw = dumps(event)
        row = db.execute("SELECT digest FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
        prev = row[0] if row else '0'*64
        h = hashlib.sha256(bytes.fromhex(prev)+raw).hexdigest()
        db.execute("INSERT INTO audit(prev,digest,body) VALUES(?,?,?)", (prev,h,raw))

    def audit(self, event):
        with self.transaction() as db: self._audit(db,event)

    def verify_audit(self):
        with self.lock:
            prev='0'*64
            for old,h,raw in self.db.execute("SELECT prev,digest,body FROM audit ORDER BY seq"):
                require(old == prev and hashlib.sha256(bytes.fromhex(prev)+raw).hexdigest() == h,
                        "AUDIT_CORRUPT", "Audit chain integrity check failed")
                prev=h
            return prev

    def install_mandate(self, mandate: Mandate, *, owner_authorized: bool):
        require(owner_authorized is True, "OWNER_REQUIRED", "Owner authorization required")
        with self.transaction() as db:
            db.execute("INSERT OR IGNORE INTO mandates VALUES(?,?, '0','0',0)", (mandate.id,dumps(asdict(mandate))))
            self._audit(db,{"type":"mandate_installed","id":mandate.id})
        return mandate.id

    def revoke(self, mandate_id, *, owner_authorized):
        require(owner_authorized is True, "OWNER_REQUIRED", "Owner authorization required")
        with self.transaction() as db:
            require(db.execute("UPDATE mandates SET revoked=1 WHERE id=?",(mandate_id,)).rowcount == 1,
                    "NOT_FOUND","Mandate not found")
            self._audit(db,{"type":"mandate_revoked","id":mandate_id})
        # Existing locked swaps retain recovery authority, never new funding authority.

    def reserve(self, quote: Quote, mandate_id, principal, max_local_fee_atoms, now, *, db=None, check_only=False):
        fee=atoms(max_local_fee_atoms)
        cost=atoms(quote.sell_atoms)+fee
        rid=digest("BTX/SWAPNET/RESERVATION/1", {"quote_id":quote.id,"principal":principal,"mandate_id":mandate_id,"fee":max_local_fee_atoms})
        with (self.transaction() if db is None else nullcontext(db)) as db:
            existing=db.execute("SELECT id FROM reservations WHERE quote_id=?",(quote.id,)).fetchone()
            if existing:
                require(existing[0] == rid,"IDEMPOTENCY_CONFLICT","Quote already reserved with different parameters")
                return rid
            require(quote.live(now),"QUOTE_EXPIRED","Expired quote")
            row=db.execute("SELECT body,held,used,revoked FROM mandates WHERE id=?",(mandate_id,)).fetchone()
            require(row is not None,"MANDATE_MISSING","Mandate not installed")
            mandate=Mandate(**loads(row[0]))
            require(not row[3] and now < mandate.expires_at,"MANDATE_EXPIRED","Mandate expired or revoked")
            require(mandate.principal == principal and quote.sell_asset == mandate.asset,"MANDATE_SCOPE","Mandate does not authorize this principal/asset")
            require(atoms(quote.sell_atoms) <= atoms(mandate.max_trade_atoms) and fee <= atoms(mandate.max_fee_atoms),"BUDGET_LIMIT","Trade or fee exceeds cap")
            held,used=atoms(row[1]),atoms(row[2])
            require(held+used+cost <= atoms(mandate.max_total_atoms),"BUDGET_LIMIT","Cumulative cap exceeded")
            if check_only:
                return rid
            db.execute("INSERT INTO reservations VALUES(?,?,?,?,?,'held',?)",(rid,quote.id,mandate_id,principal,str(cost),dumps(asdict(quote))))
            db.execute("UPDATE mandates SET held=? WHERE id=?",(str(held+cost),mandate_id))
            self._audit(db,{"type":"reserved","id":rid,"quote_id":quote.id,"cost_atoms":str(cost)})
        return rid

    def lock_coins(self, reservation_id, chain, outpoints):
        require(len(outpoints) == len(set(outpoints)) and 0 < len(outpoints) <= 256,"COINLOCK","Duplicate or too many inputs")
        with self.transaction() as db:
            row=db.execute("SELECT state FROM reservations WHERE id=?",(reservation_id,)).fetchone()
            require(row is not None and row[0] == 'held',"RESERVATION","Reservation not available")
            for outpoint in outpoints:
                old=db.execute("SELECT reservation_id FROM coinlocks WHERE chain=? AND outpoint=?",(chain,outpoint)).fetchone()
                require(old is None or old[0] == reservation_id,"INPUT_RESERVED","Input already reserved by another swap")
                db.execute("INSERT OR IGNORE INTO coinlocks VALUES(?,?,?)",(chain,outpoint,reservation_id))

    def mark_funded(self, reservation_id):
        with self.transaction() as db:
            row=db.execute("SELECT state FROM reservations WHERE id=?",(reservation_id,)).fetchone()
            require(row is not None and row[0] in {'held','funded'},"RESERVATION","Invalid reservation")
            db.execute("UPDATE reservations SET state='funded' WHERE id=?",(reservation_id,))

    def settle_reservation(self, reservation_id, actual_cost_atoms, *, verified_terminal=False):
        cost=atoms(actual_cost_atoms)
        with self.transaction() as db:
            self._settle_reservation(db, reservation_id, cost, verified_terminal=verified_terminal)

    def _settle_reservation(self, db, reservation_id, cost, *, verified_terminal=False):
        row=db.execute("SELECT mandate_id,cost,state FROM reservations WHERE id=?",(reservation_id,)).fetchone()
        require(row is not None,"NOT_FOUND","Reservation not found")
        require(row[2] in {'held','funded'},"RESERVATION_FINAL","Reservation already finalized")
        require(row[2] != 'funded' or verified_terminal is True,"FUNDS_LOCKED","Do not release a funded swap before verified terminal settlement")
        require(cost <= atoms(row[1]),"BUDGET_LIMIT","Actual cost exceeds reserved cap")
        held,used=db.execute("SELECT held,used FROM mandates WHERE id=?",(row[0],)).fetchone()
        db.execute("UPDATE mandates SET held=?,used=? WHERE id=?",(str(atoms(held)-atoms(row[1])),str(atoms(used)+cost),row[0]))
        db.execute("UPDATE reservations SET state='closed' WHERE id=?",(reservation_id,))
        db.execute("DELETE FROM coinlocks WHERE reservation_id=?",(reservation_id,))
        self._audit(db,{"type":"reservation_closed","id":reservation_id,"actual_cost_atoms":str(cost)})

    def save_session(self, sid, body, expected_revision=-1):
        hex32(sid); integer(expected_revision,lo=-1)
        raw=dumps(body)
        with self.transaction() as db:
            old=db.execute("SELECT revision,body FROM sessions WHERE id=?",(sid,)).fetchone()
            actual=old[0] if old else -1
            require(actual == expected_revision,"REVISION_CONFLICT","Session changed concurrently")
            if old:
                previous=loads(old[1])
                old_state=previous.get('state',previous)
                new_state=body.get('state',body)
                require(not old_state.get('secret_exposed',False) or new_state.get('secret_exposed') is True,
                        'SECRET_ROLLBACK','Secret exposure is irreversible')
            revision=actual+1
            db.execute("INSERT INTO sessions VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET revision=excluded.revision,body=excluded.body",(sid,revision,raw))
            self._audit(db,{"type":"session_saved","id":sid,"revision":revision,"state_hash":digest("BTX/SWAPNET/STATE/1",body)})
            return revision

    def load_session(self,sid):
        with self.lock:
            row=self.db.execute("SELECT revision,body FROM sessions WHERE id=?",(sid,)).fetchone()
            require(row is not None,"NOT_FOUND","Session not found")
            return row[0],loads(row[1])

    def list_sessions(self,limit=100):
        integer(limit,lo=1,hi=1000)
        with self.lock: return [loads(r[0]) for r in self.db.execute("SELECT body FROM sessions ORDER BY id LIMIT ?",(limit,))]

    def prepare_operation(self, op_id, chain, kind, txid, raw):
        hex32(op_id); hex32(txid)
        require(type(raw) is str and 0 < len(raw) <= 2_000_000 and len(raw)%2 == 0,"RAW_TX","Invalid raw transaction")
        try: bytes.fromhex(raw)
        except ValueError as e: raise SwapError("RAW_TX","Invalid raw transaction") from e
        require(kind in {'fund','claim','refund','fee_bump'},"OPERATION","Invalid operation kind")
        with self.transaction() as db:
            old=db.execute("SELECT chain,kind,txid,raw FROM operations WHERE id=?",(op_id,)).fetchone()
            if old:
                require(old == (chain,kind,txid,raw),"IDEMPOTENCY_CONFLICT","Operation bytes changed")
                return
            db.execute("INSERT INTO operations VALUES(?,?,?,?,?,'prepared')",(op_id,chain,kind,txid,raw))
            self._audit(db,{"type":"operation_prepared","id":op_id,"txid":txid,"kind":kind})

    def broadcast_operation(self,op_id,broadcast):
        with self.lock:
            row=self.db.execute("SELECT txid,raw,state FROM operations WHERE id=?",(op_id,)).fetchone()
        require(row is not None,"NOT_FOUND","Operation missing")
        if row[2] == 'broadcast': return row[0]
        result=broadcast(row[1])  # Failure leaves prepared row intact; caller reconciles before retry.
        require(result == row[0],"TXID_MISMATCH","Node returned unexpected transaction ID")
        with self.transaction() as db:
            db.execute("UPDATE operations SET state='broadcast' WHERE id=?",(op_id,))
            self._audit(db,{"type":"operation_broadcast","id":op_id,"txid":result})
        return result

    def cancel_session(self,sid,principal):
        with self.transaction() as db:
            row=db.execute('SELECT revision,body FROM sessions WHERE id=?',(sid,)).fetchone()
            require(row is not None,'NOT_FOUND','Session missing')
            b=loads(row[1]);state=b['state']
            require(b['principal']==principal,'FORBIDDEN','Session belongs to another principal')
            require(not state['funding_prepared'] and not state['funding_broadcast'],'FUNDS_LOCKED','Cannot cancel prepared/funded swap')
            r=db.execute('SELECT mandate_id,cost,state FROM reservations WHERE id=?',(b['reservation_id'],)).fetchone()
            require(r is not None and r[2]=='held','RESERVATION_FINAL','Reservation not cancelable')
            held=db.execute('SELECT held FROM mandates WHERE id=?',(r[0],)).fetchone()[0]
            db.execute('UPDATE mandates SET held=? WHERE id=?',(str(atoms(held)-atoms(r[1])),r[0]))
            db.execute("UPDATE reservations SET state='closed' WHERE id=?",(b['reservation_id'],))
            db.execute('DELETE FROM coinlocks WHERE reservation_id=?',(b['reservation_id'],))
            state['phase']='cancelled';state['authorized']=False
            db.execute('UPDATE sessions SET revision=?,body=? WHERE id=?',(row[0]+1,dumps(b),sid))
            self._audit(db,{'type':'session_cancelled','id':sid})
            return b
