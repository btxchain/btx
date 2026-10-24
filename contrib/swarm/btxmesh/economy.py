"""SEP/1 non-custodial objective accounting, NOT an implementation of L1 scripts.

Backings are live UTXO observations with exact script matching. That alone does
not prove an exclusive economic pledge, refund rights, or channel enforceability.
No method in this module signs or broadcasts a monetary transaction. Earned
receipts remain explicitly unsecured until a qualified native channel backend
produces and verifies an independently redeemable claim.
"""
import time
from .codec import encode,decode,digest,atoms,fixed_id,integer,fields
from .errors import MeshError,require
from .storage import Database


class Ledger:
    def __init__(self,path):
        self.db=Database(path)
        self.db.db.executescript('''
        CREATE TABLE IF NOT EXISTS pools(id TEXT PRIMARY KEY,body TEXT,status TEXT);
        CREATE TABLE IF NOT EXISTS backing(outpoint TEXT PRIMARY KEY,pool TEXT,amount INTEGER,fee_reserve INTEGER,block_hash TEXT,height INTEGER,checked_ms INTEGER,state TEXT,script TEXT);
        CREATE TABLE IF NOT EXISTS mandates(id TEXT PRIMARY KEY,pool TEXT,actor TEXT,amount INTEGER,used INTEGER,expires_ms INTEGER,recipients TEXT,revoked INTEGER);
        CREATE TABLE IF NOT EXISTS obligations(id TEXT PRIMARY KEY,pool TEXT,work TEXT,worker TEXT,amount INTEGER,state TEXT,mandate TEXT,receipt TEXT,terms TEXT,UNIQUE(pool,work));
        CREATE TABLE IF NOT EXISTS economy_events(id INTEGER PRIMARY KEY AUTOINCREMENT,kind TEXT,body TEXT);
        ''')
    def event(self,c,kind,body):c.execute('INSERT INTO economy_events(kind,body) VALUES(?,?)',(kind,encode(body).decode()))
    def create_pool(self,manifest):
        fields(manifest,{'lineage_id','objective_id','chain_genesis','policy_id','nonce','owner','refund_terms_id','work_policy_id'})
        for key in ('lineage_id','objective_id','policy_id','owner','refund_terms_id','work_policy_id'):fixed_id(manifest[key])
        require(isinstance(manifest['chain_genesis'],str) and len(manifest['chain_genesis'])==64,'CHAIN_GENESIS')
        id=digest('BTX/SwarmPool/1',manifest)
        with self.db.tx() as c:
            old=c.execute('SELECT body FROM pools WHERE id=?',(id,)).fetchone()
            if old:require(old[0]==encode(manifest).decode(),'POOL_CONFLICT');return id
            c.execute('INSERT INTO pools VALUES(?,?,?)',(id,encode(manifest).decode(),'UNFUNDED'))
            self.event(c,'POOL_CREATED',{'pool':id})
        return id
    def pool(self,c,id):
        row=c.execute('SELECT body,status FROM pools WHERE id=?',(id,)).fetchone();require(row is not None,'POOL_NOT_FOUND')
        return decode(row[0].encode()),row[1]
    def observe_backing(self,pool_id,observation,*,expected_script,fee_reserve_atoms='0'):
        """Input comes from L1Observer, never from a swarm peer's balance claim.

        This local API deliberately records OBSERVED_UNSPENT, not ENFORCEABLE.
        An operator with access to this process is trusted for local accounting.
        """
        fields(observation,{'outpoint','genesis','atoms','confirmations','height','block_hash','script','checked_ms'})
        require(observation['script']==expected_script and bool(expected_script),'BACKING_SCRIPT')
        integer(observation['confirmations'],1,10**9);amount=atoms(observation['atoms']);reserve=atoms(fee_reserve_atoms)
        require(amount>0 and 0<=reserve<amount,'FEE_RESERVE')
        require(0<=int(time.time()*1000)-observation['checked_ms']<=30000,'BACKING_STALE')
        with self.db.tx() as c:
            pool,_=self.pool(c,pool_id);require(pool['chain_genesis']==observation['genesis'],'WRONG_CHAIN')
            old=c.execute('SELECT * FROM backing WHERE outpoint=?',(observation['outpoint'],)).fetchone()
            if old:
                require(old['pool']==pool_id,'BACKING_ALREADY_ALLOCATED')
                require(old['amount']==amount and old['script']==expected_script and old['fee_reserve']==reserve,'BACKING_MUTATION')
                c.execute('UPDATE backing SET block_hash=?,height=?,checked_ms=?,state=? WHERE outpoint=?',(observation['block_hash'],observation['height'],observation['checked_ms'],'OBSERVED_UNSPENT',observation['outpoint']))
            else:
                c.execute('INSERT INTO backing VALUES(?,?,?,?,?,?,?,?,?)',(observation['outpoint'],pool_id,amount,reserve,observation['block_hash'],observation['height'],observation['checked_ms'],'OBSERVED_UNSPENT',expected_script))
            c.execute("UPDATE pools SET status='ACCOUNTING_ONLY' WHERE id=?",(pool_id,))
            self.event(c,'BACKING_OBSERVED',{'pool':pool_id,'outpoint':observation['outpoint'],'atoms':str(amount),'assurance':'UTXO_OBSERVATION_NOT_ENFORCEABLE_PLEDGE'})
        return self.balances(pool_id)
    def invalidate_backing(self,outpoint,reason):
        require(reason in {'SPENT','REORG','STALE','CONFLICT'},'BACKING_STATE')
        with self.db.tx() as c:
            row=c.execute('SELECT pool FROM backing WHERE outpoint=?',(outpoint,)).fetchone();require(row is not None,'BACKING_NOT_FOUND')
            c.execute('UPDATE backing SET state=? WHERE outpoint=?',(reason,outpoint));c.execute("UPDATE pools SET status='FROZEN' WHERE id=?",(row[0],))
            self.event(c,'BACKING_INVALIDATED',{'outpoint':outpoint,'reason':reason})
        # Obligations are retained. A reorg cannot erase earned claims.
    def grant_mandate(self,*,pool,actor,limit_atoms,expires_ms,recipients,nonce):
        amount=atoms(limit_atoms);fixed_id(actor)
        require(amount>0 and int(time.time()*1000)<expires_ms<=int(time.time()*1000)+30*86400000,'MANDATE_LIMIT')
        require(isinstance(recipients,list) and 1<=len(recipients)<=1024,'RECIPIENTS')
        for peer in recipients:fixed_id(peer)
        body={'pool':pool,'actor':actor,'atoms':str(amount),'expires_ms':expires_ms,'recipients':sorted(set(recipients)),'nonce':nonce}
        id=digest('BTX/LocalPaymentMandate/1',body)
        with self.db.tx() as c:
            self.pool(c,pool)
            c.execute('INSERT OR IGNORE INTO mandates VALUES(?,?,?,?,?,?,?,0)',(id,pool,actor,amount,0,expires_ms,encode(body['recipients']).decode()))
            self.event(c,'MANDATE_GRANTED',{'id':id,'enforcement':'LOCAL_ACCOUNTING_ONLY'})
        return id
    def revoke_mandate(self,id):
        with self.db.tx() as c:c.execute('UPDATE mandates SET revoked=1 WHERE id=?',(id,));self.event(c,'MANDATE_REVOKED',{'id':id})
    def _balance(self,c,pool,now_ms):
        rows=c.execute('SELECT * FROM backing WHERE pool=?',(pool,)).fetchall()
        backing=sum(r['amount'] for r in rows if r['state']=='OBSERVED_UNSPENT' and now_ms-r['checked_ms']<=30000)
        reserve=sum(r['fee_reserve'] for r in rows if r['state']=='OBSERVED_UNSPENT' and now_ms-r['checked_ms']<=30000)
        obligations=c.execute("SELECT amount,state FROM obligations WHERE pool=? AND state!='CANCELLED'",(pool,)).fetchall()
        pending=sum(r['amount'] for r in obligations if r['state']=='RESERVED')
        earned=sum(r['amount'] for r in obligations if r['state']=='EARNED_UNSECURED')
        liability=pending+earned
        return {'observed_unspent_atoms':str(backing),'fee_reserve_atoms':str(reserve),'pending_atoms':str(pending),'earned_unsecured_atoms':str(earned),
                'accounting_available_atoms':str(max(0,backing-reserve-liability)),'backing_deficit_atoms':str(max(0,reserve+liability-backing)),
                'immediately_payable_l2_atoms':'0','enforceable_channel_claim_atoms':'0','assurance':'ACCOUNTING_ONLY_NOT_A_PAYMENT_NETWORK'}
    def balances(self,pool):
        with self.db.tx() as c:self.pool(c,pool);return self._balance(c,pool,int(time.time()*1000))
    def reserve(self,*,mandate,actor,work,worker,amount_atoms,terms_id,accept_unsecured_credit=False):
        amount=atoms(amount_atoms);require(amount>0,'AMOUNT');fixed_id(worker);fixed_id(terms_id)
        require(accept_unsecured_credit is True,'ENFORCEABLE_CHANNEL_REQUIRED','reference ledger only supports explicitly accepted unsecured terms')
        with self.db.tx() as c:
            m=c.execute('SELECT * FROM mandates WHERE id=?',(mandate,)).fetchone();require(m is not None,'MANDATE')
            _,status=self.pool(c,m['pool']);require(status!='FROZEN','POOL_FROZEN')
            require(m['actor']==actor and not m['revoked'] and m['expires_ms']>int(time.time()*1000),'MANDATE_AUTH')
            require(worker in decode(m['recipients'].encode()),'RECIPIENT_AUTH')
            old=c.execute('SELECT * FROM obligations WHERE pool=? AND work=?',(m['pool'],work)).fetchone()
            if old:
                require(old['worker']==worker and old['amount']==amount and old['mandate']==mandate and old['terms']==terms_id,'OBLIGATION_CONFLICT')
                return {'reservation':old['id'],'state':old['state'],'enforcement':'UNSECURED_EXPLICITLY_ACCEPTED'}
            require(m['used']+amount<=m['amount'],'MANDATE_EXHAUSTED')
            available=atoms(self._balance(c,m['pool'],int(time.time()*1000))['accounting_available_atoms']);require(amount<=available,'INSUFFICIENT_UNRESERVED_BACKING')
            id=digest('BTX/WorkReservation/1',{'pool':m['pool'],'work':work,'worker':worker,'atoms':str(amount),'terms':terms_id})
            c.execute('INSERT INTO obligations VALUES(?,?,?,?,?,?,?,?,?)',(id,m['pool'],work,worker,amount,'RESERVED',mandate,'',terms_id))
            c.execute('UPDATE mandates SET used=used+? WHERE id=?',(amount,mandate))
            self.event(c,'RESERVED',{'reservation':id,'amount_atoms':str(amount)})
            return {'reservation':id,'state':'RESERVED','enforcement':'UNSECURED_EXPLICITLY_ACCEPTED'}
    def accept_work(self,reservation,receipt_id):
        fixed_id(receipt_id)
        with self.db.tx() as c:
            r=c.execute('SELECT * FROM obligations WHERE id=?',(reservation,)).fetchone();require(r is not None,'RESERVATION')
            require(r['state'] in {'RESERVED','EARNED_UNSECURED'},'OBLIGATION_STATE')
            require(not r['receipt'] or r['receipt']==receipt_id,'RECEIPT_CONFLICT')
            c.execute("UPDATE obligations SET state='EARNED_UNSECURED',receipt=? WHERE id=?",(receipt_id,reservation))
            self.event(c,'WORK_ACCEPTED_NOT_PAID',{'reservation':reservation,'receipt':receipt_id})
            return {'earned_atoms':str(r['amount']),'payment_status':'EARNED_UNSECURED','l1_transaction':None}
    def cancel(self,reservation):
        with self.db.tx() as c:
            r=c.execute('SELECT * FROM obligations WHERE id=?',(reservation,)).fetchone();require(r is not None,'RESERVATION')
            require(r['state'] in {'RESERVED','CANCELLED'},'EARNED_OBLIGATION_CANNOT_BE_CANCELLED')
            if r['state']=='CANCELLED':return
            c.execute("UPDATE obligations SET state='CANCELLED' WHERE id=?",(reservation,));c.execute('UPDATE mandates SET used=used-? WHERE id=?',(r['amount'],r['mandate']))
            self.event(c,'RESERVATION_CANCELLED',{'reservation':reservation})
    def settle(self,*args,**kwargs):
        raise MeshError('NATIVE_CHANNEL_BACKEND_UNQUALIFIED','no transaction is signed or broadcast by this build')
    def close(self):self.db.close()
