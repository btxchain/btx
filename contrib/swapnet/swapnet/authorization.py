"""Authenticated owner/agent budgets enforced immediately before every signature.

The native caller constructs Principal; JSON never supplies roles. A PeerPrincipal
is intentionally a different type and cannot enter owner or signing methods.
A grant freezes the exact agreement, asset, key roles, destinations and fee budget.
"""
from dataclasses import dataclass,asdict
import time
from .canonical import atoms,hex32,digest,dumps,loads,integer
from .errors import require,SwapError
from .journal import local_dump,local_load
from .policy import Mandate

@dataclass(frozen=True)
class Principal:
    name:str
    owner:bool=False
    wallet:str=''
    def __post_init__(self):
        require(type(self.name) is str and 0<len(self.name)<=128,'PRINCIPAL','Invalid authenticated principal')
        require(type(self.owner) is bool,'PRINCIPAL','Invalid role')

@dataclass(frozen=True)
class PeerPrincipal:
    identity:str

@dataclass(frozen=True)
class Grant:
    principal:str
    swap_id:str
    agreement_id:str
    reservation_id:str
    asset:str
    amount_atoms:str
    max_fee_atoms:str
    funding_script:str
    refund_payout:str
    receive_payout:str
    expires_at:int
    @property
    def id(self):return digest('BTX/SWAPNET/GRANT/2',asdict(self))

class Authority:
    def __init__(self,store,journal,clock=None):
        self.store,self.journal=store,journal;self.clock=clock or (lambda:int(time.time()))
    @staticmethod
    def owner(ctx):require(type(ctx) is Principal and ctx.owner,'OWNER_REQUIRED','Native owner authentication required')
    def install(self,ctx,body):
        self.owner(ctx);mandate=Mandate(**body)
        require(mandate.expires_at>self.clock(),'MANDATE_EXPIRED','Mandate already expired')
        return self.store.install_mandate(mandate,owner_authorized=True)
    def revoke(self,ctx,mid):
        self.owner(ctx);self.store.revoke(hex32(mid),owner_authorized=True)
        with self.store.transaction() as db:
            rows=db.execute('SELECT id,body,consumed FROM sn_grants').fetchall()
            for gid,raw,consumed in rows:
                g=local_load(raw)
                rr=db.execute('SELECT mandate_id FROM reservations WHERE id=?',(g['reservation_id'],)).fetchone()
                if rr and rr[0]==mid and not consumed:db.execute('UPDATE sn_grants SET revoked=1 WHERE id=?',(gid,))
    def reserve(self,ctx,quote,mandate_id,max_fee_atoms):
        require(type(ctx) is Principal,'AUTH','Peer cannot reserve wallet funds')
        return self.store.reserve(quote,mandate_id,ctx.name,max_fee_atoms,self.clock())
    def reservation_expiry(self,rid):
        with self.store.lock:
            row=self.store.db.execute('SELECT m.body FROM mandates m JOIN reservations r ON r.mandate_id=m.id WHERE r.id=?',(rid,)).fetchone()
        require(row is not None,'RESERVATION','Missing reservation')
        return loads(row[0])['expires_at']
    def grant(self,ctx,grant):
        require(type(ctx) is Principal and ctx.name==grant.principal,'AUTH','Grant principal mismatch')
        hex32(grant.swap_id);hex32(grant.agreement_id);atoms(grant.amount_atoms,positive=True);atoms(grant.max_fee_atoms)
        with self.store.transaction() as db:
            r=db.execute('SELECT principal,cost,state,mandate_id FROM reservations WHERE id=?',(grant.reservation_id,)).fetchone()
            require(r and r[0]==ctx.name and r[2]=='held','RESERVATION','No active reservation')
            require(atoms(grant.amount_atoms)+atoms(grant.max_fee_atoms)<=atoms(r[1]),'BUDGET_LIMIT','Grant exceeds reservation')
            m=db.execute('SELECT body,revoked FROM mandates WHERE id=?',(r[3],)).fetchone()
            require(m and not m[1] and loads(m[0])['expires_at']>self.clock(),'MANDATE_EXPIRED','Funding authorization expired')
            db.execute('INSERT OR IGNORE INTO sn_grants VALUES(?,?,?,?,?,0,0)',(grant.id,ctx.name,grant.swap_id,local_dump(asdict(grant)),r[1]))
        return grant.id
    def check(self,grant_id,agreement_id,*,kind,asset,amount_atoms='0',fee_atoms='0',destination='',funding_script=''):
        """Return frozen Grant; caller must use it, not unvalidated peer fields."""
        with self.store.lock:
            row=self.store.db.execute('SELECT body,consumed,revoked FROM sn_grants WHERE id=?',(hex32(grant_id),)).fetchone()
        require(row is not None,'GRANT_MISSING','Signing grant missing')
        g=Grant(**local_load(row[0]))
        require(g.agreement_id==agreement_id and g.asset==asset,'SIGNER_SCOPE','Wrong agreement or asset')
        require(atoms(fee_atoms)<=atoms(g.max_fee_atoms),'FEE_CAP','Fee exceeds signing grant')
        if kind=='fund':
            require(not row[2] and self.clock()<g.expires_at,'GRANT_REVOKED','New funding is not authorized')
            require(atoms(amount_atoms)==atoms(g.amount_atoms) and funding_script==g.funding_script,'SIGNER_SCOPE','Funding commitment changed')
            with self.store.lock:
                r=self.store.db.execute('SELECT m.body,m.revoked FROM mandates m JOIN reservations r ON r.mandate_id=m.id WHERE r.id=?',(g.reservation_id,)).fetchone()
            require(r and not r[1] and loads(r[0])['expires_at']>self.clock(),'MANDATE_REVOKED','Mandate expired or revoked')
        elif kind=='refund':require(destination==g.refund_payout,'SIGNER_SCOPE','Refund destination changed')
        else:raise SwapError('SIGNER_SCOPE','Use receive-side claim authority for a different asset')
        return g
    def mark_consumed(self,grant_id):
        with self.store.transaction() as db:
            row=db.execute('SELECT body FROM sn_grants WHERE id=?',(grant_id,)).fetchone()
            require(row is not None,'GRANT_MISSING','Grant not found')
            g=Grant(**local_load(row[0]))
            db.execute('UPDATE sn_grants SET consumed=1 WHERE id=?',(grant_id,))
            db.execute("UPDATE reservations SET state='funded' WHERE id=?",(g.reservation_id,))
    def permit_existing_funding(self,grant_id):
        with self.store.lock:r=self.store.db.execute('SELECT consumed,revoked,body FROM sn_grants WHERE id=?',(grant_id,)).fetchone()
        require(r is not None,'GRANT_MISSING','Grant missing')
        # Signed and durably recorded funding may already have escaped before a crash.
        return bool(r[0])
    def terminal(self,grant_id):
        with self.store.lock:r=self.store.db.execute('SELECT body,reserved FROM sn_grants WHERE id=?',(grant_id,)).fetchone()
        if not r:return
        g=Grant(**local_load(r[0]))
        with self.store.lock:state=self.store.db.execute('SELECT state FROM reservations WHERE id=?',(g.reservation_id,)).fetchone()
        if state and state[0]!='closed':
            # Deliberately do not recycle trade principal automatically after a refund.
            # A deep reorg must never restore authorization already spent elsewhere.
            self.store.settle_reservation(g.reservation_id,r[1],verified_terminal=True)
