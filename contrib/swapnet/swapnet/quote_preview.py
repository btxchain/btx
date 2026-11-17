"""Durable preview/confirmation binding. Preview does not reserve or sign funds."""
import json
import secrets
from .market_controls import canonical, fingerprint, require

class PreviewStore:
    def __init__(self,store,clock):
        self.store,self.now=store,clock
        with store.transaction() as db:
            db.execute('CREATE TABLE IF NOT EXISTS sn_liquidity_previews(id TEXT PRIMARY KEY,principal TEXT NOT NULL,wallet TEXT NOT NULL,expires INTEGER NOT NULL,body BLOB NOT NULL,swap_id TEXT)')
            db.execute('CREATE INDEX IF NOT EXISTS sn_liquidity_preview_expiry ON sn_liquidity_previews(expires)')
    def create(self,principal,wallet,quote,parameters,policy_digest):
        now=self.now();expires=min(quote['expires_at'],now+30)
        require(expires>now,'QUOTE_EXPIRED','Quote is no longer executable')
        body={'quote':quote,'parameters':parameters,'policy_digest':policy_digest,'created_at':now,
              'expires_at':expires,'principal':principal,'wallet':wallet,'nonce':secrets.token_hex(32)}
        pid=fingerprint(body)
        with self.store.transaction() as db:
            db.execute('DELETE FROM sn_liquidity_previews WHERE expires<=? AND swap_id IS NULL',(now,))
            # Completed preview acknowledgements retained for one day, then safely forgotten.
            db.execute('DELETE FROM sn_liquidity_previews WHERE expires<?',(now-86400,))
            require(db.execute('SELECT COUNT(*) FROM sn_liquidity_previews').fetchone()[0]<2048,'PREVIEW_LIMIT','Preview capacity reached')
            require(db.execute('SELECT COUNT(*) FROM sn_liquidity_previews WHERE principal=? AND swap_id IS NULL',(principal,)).fetchone()[0]<32,'PREVIEW_LIMIT','Caller preview capacity reached')
            db.execute('INSERT INTO sn_liquidity_previews VALUES(?,?,?,?,?,NULL)',(pid,principal,wallet,expires,canonical(body)))
        return pid,body
    def read(self,pid,principal,wallet):
        with self.store.lock:
            row=self.store.db.execute('SELECT principal,wallet,body,swap_id FROM sn_liquidity_previews WHERE id=?',(pid,)).fetchone()
        require(row is not None and row[0]==principal and row[1]==wallet,'PREVIEW_SCOPE','Preview unavailable to this wallet/principal')
        body=json.loads(row[2]);require(fingerprint(body)==pid,'PREVIEW_CORRUPT','Preview digest does not match')
        return body,row[3]
    def complete(self,pid,principal,wallet,swap_id):
        # Coordinator.start is idempotent by signed quote ID. If this write fails,
        # a retry reconciles that same session instead of minting a second trade.
        self.read(pid,principal,wallet)
        with self.store.transaction() as db:
            row=db.execute('SELECT swap_id FROM sn_liquidity_previews WHERE id=?',(pid,)).fetchone()
            require(row is not None and (row[0] is None or row[0]==swap_id),'PREVIEW_CONFLICT','Conflicting completion')
            db.execute('UPDATE sn_liquidity_previews SET swap_id=? WHERE id=?',(swap_id,pid))
