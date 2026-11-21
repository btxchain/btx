"""Opt-in signed public offers and durable, locally reserved maker capacity.

A signature authenticates terms, not solvency. A firm offer reserves this node's
capacity; it is not an on-chain guarantee. Actual execution still requires a
requester-bound Quote and the existing independently verified HTLC agreement.
All database methods use the production Store transaction/lock contracts.
"""
from __future__ import annotations

from dataclasses import asdict
import secrets
from typing import Any, Callable

from .assets import Asset
from .canonical import atoms, digest, dumps, exact_fields, hex32, integer, loads
from .errors import SwapError, require
from .store import apply_script
from .marketmaker import Market
from .quote import Quote

DOMAIN = 'BTX/SWAPNET/PUBLIC-OFFER/1'
MAX_TTL = 300
MAX_RECORD = 24576
MAX_OFFERS = 2048
MAX_PER_PROVIDER = 64
MAX_IDENTITIES = 8192
MAX_TIERS = 8
MAX_SLOTS = 64
OFFER_FIELDS = {'version','network','provider','offer_id','sequence','issued_at',
                'expires_at','kind','sell_asset','buy_asset','tiers','withdrawn'}
TIER_FIELDS = {'sell_atoms','buy_atoms','maker_fee_atoms',
               'max_receive_network_fee_atoms','slots'}

SCHEMA = '''
CREATE TABLE IF NOT EXISTS sn_public_offers(
 provider TEXT NOT NULL, offer_id TEXT NOT NULL, sequence INTEGER NOT NULL,
 expires INTEGER NOT NULL, body BLOB NOT NULL, local INTEGER NOT NULL DEFAULT 0,
 PRIMARY KEY(provider,offer_id));
CREATE TABLE IF NOT EXISTS sn_public_sequences(
 provider TEXT NOT NULL, offer_id TEXT NOT NULL, sequence INTEGER NOT NULL,
 record_hash TEXT NOT NULL, expires INTEGER NOT NULL,
 PRIMARY KEY(provider,offer_id));
CREATE TABLE IF NOT EXISTS sn_public_slots(
 slot_id TEXT PRIMARY KEY, offer_id TEXT NOT NULL, sequence INTEGER NOT NULL,
 tier INTEGER NOT NULL, mandate_id TEXT NOT NULL, principal TEXT NOT NULL,
 sell_asset TEXT NOT NULL, buy_asset TEXT NOT NULL, sell_atoms TEXT NOT NULL,
 buy_atoms TEXT NOT NULL, maker_fee_atoms TEXT NOT NULL,
 fee_atoms TEXT NOT NULL, expires INTEGER NOT NULL, state TEXT NOT NULL,
 nonce TEXT, requester TEXT, quote_id TEXT, rfq_id TEXT, reservation_id TEXT,
 policy BLOB NOT NULL);
CREATE INDEX IF NOT EXISTS sn_public_slot_mandate ON sn_public_slots(mandate_id,state,expires);
CREATE INDEX IF NOT EXISTS sn_public_slot_offer ON sn_public_slots(offer_id,tier,state);
CREATE UNIQUE INDEX IF NOT EXISTS sn_public_slot_rfq ON sn_public_slots(rfq_id) WHERE rfq_id IS NOT NULL;
CREATE TABLE IF NOT EXISTS sn_public_requests(
 request_id TEXT PRIMARY KEY, principal TEXT NOT NULL, provider TEXT NOT NULL,
 body BLOB NOT NULL, expires INTEGER NOT NULL, next_try INTEGER NOT NULL,
 attempts INTEGER NOT NULL DEFAULT 0, completed INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS sn_market_refusals(
 request_id TEXT NOT NULL, provider TEXT NOT NULL, envelope BLOB NOT NULL,
 observed INTEGER NOT NULL, PRIMARY KEY(request_id,provider));
'''


def signing_message(body: dict) -> str:
    return DOMAIN + ':' + digest(DOMAIN, body)


def validate_offer(envelope: dict, network: str, now: int,
                   verify: Callable[[str, str, str], bool]) -> dict:
    exact_fields(envelope, {'body', 'signature'})
    body = envelope['body']
    exact_fields(body, OFFER_FIELDS)
    require(type(body['version']) is int and body['version'] == 1,
            'OFFER_VERSION', 'Unsupported public offer version')
    require(hex32(body['network']) == network, 'NETWORK', 'Wrong offer network')
    hex32(body['offer_id']); integer(body['sequence'], lo=1)
    integer(body['issued_at']); integer(body['expires_at'])
    require(body['issued_at'] <= now < body['expires_at'] <= body['issued_at'] + MAX_TTL,
            'OFFER_EXPIRED', 'Offer expired, future-dated, or excessive lifetime')
    require(type(body['provider']) is str and 0 < len(body['provider']) <= 256,
            'IDENTITY', 'Invalid provider identity')
    require(body['kind'] in ('indicative', 'firm'), 'OFFER_KIND', 'Unknown offer kind')
    require(type(body['withdrawn']) is bool, 'OFFER_WITHDRAWN', 'Invalid withdrawal flag')
    a, b = Asset.parse(body['sell_asset']), Asset.parse(body['buy_asset'])
    require(a.id != b.id and 'btx' in (a.family,b.family), 'PAIR', 'Native BTX pair required')
    require(type(body['tiers']) is list and 1 <= len(body['tiers']) <= MAX_TIERS,
            'OFFER_TIERS', 'One to eight exact quantity tiers required')
    seen = set()
    for tier in body['tiers']:
        exact_fields(tier, TIER_FIELDS)
        amount = atoms(tier['sell_atoms'], positive=True)
        require(amount not in seen, 'OFFER_TIERS', 'Duplicate exact quantity')
        seen.add(amount)
        gross = atoms(tier['buy_atoms'], positive=True)
        require(gross > atoms(tier['maker_fee_atoms']) + atoms(tier['max_receive_network_fee_atoms']),
                'NET_AMOUNT', 'Offer fees consume proceeds')
        integer(tier['slots'], lo=1, hi=MAX_SLOTS)
    require(sum(t['slots'] for t in body['tiers']) <= MAX_SLOTS,
            'OFFER_SLOTS', 'At most 64 independently allocated slots per offer')
    require(type(envelope['signature']) is str and 0 < len(envelope['signature']) <= 16384,
            'SIGNATURE', 'Invalid offer signature')
    require(len(dumps(envelope)) <= MAX_RECORD, 'OFFER_SIZE', 'Offer exceeds record bound')
    require(verify(body['provider'], envelope['signature'], signing_message(body)) is True,
            'BAD_SIGNATURE', 'Public offer signature rejected')
    return body


def _table_exists(db: Any) -> bool:
    return db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='sn_public_slots'").fetchone() is not None


def _matches_reverse(row: dict, quote: Quote) -> bool:
    """Only the two production maker debit forms receive a capacity credit.

    A peer-supplied nonce alone is deliberately insufficient. A valid normal
    requester binding cannot equal either domain-separated maker binding.
    """
    if not row.get('quote_id') or not row.get('requester'):
        return False
    sid = digest('BTX/SWAPNET/SWAP/2', {'quote_id':row['quote_id'], 'initiator':row['requester']})
    expected = {
        digest('BTX/SWAPNET/MAKER/2', {'quote':row['quote_id']}),
        digest('BTX/SWAPNET/MAKER/2', {'swap_id':sid}),
    }
    return (quote.requester in expected and quote.provider == row['requester']
            and quote.nonce == row.get('nonce')
            and quote.sell_asset == row['buy_asset'] and quote.buy_asset == row['sell_asset']
            and atoms(quote.sell_atoms) == atoms(row['buy_atoms']) - atoms(row['maker_fee_atoms'])
            and atoms(quote.buy_atoms) == atoms(row['sell_atoms']))


def _live_rows(db: Any, now: int, mandate_id: str | None = None) -> list[dict]:
    if not _table_exists(db):
        return []
    sql = "SELECT slot_id,mandate_id,buy_atoms,maker_fee_atoms,fee_atoms,nonce,requester,quote_id,buy_asset,sell_asset,sell_atoms FROM sn_public_slots WHERE state IN ('available','allocating','quoted') AND expires>?"
    args: tuple = (now,)
    if mandate_id is not None:
        sql += ' AND mandate_id=?'; args += (mandate_id,)
    names = ('slot_id','mandate_id','buy_atoms','maker_fee_atoms','fee_atoms','nonce',
             'requester','quote_id','buy_asset','sell_asset','sell_atoms')
    return [dict(zip(names,r)) for r in db.execute(sql,args).fetchall()]


def reserved_budget(db: Any, mandate_id: str, quote: Quote, now: int) -> int:
    """Called inside Store.reserve's transaction, including check_only reads."""
    return sum(atoms(r['buy_atoms']) - atoms(r['maker_fee_atoms']) + atoms(r['fee_atoms'])
               for r in _live_rows(db, now, mandate_id) if not _matches_reverse(r, quote))


def transfer_to_reservation(db: Any, mandate_id: str, quote: Quote, rid: str, now: int) -> None:
    """The actual reservation and this handoff commit in the SAME transaction."""
    for row in _live_rows(db, now, mandate_id):
        if _matches_reverse(row, quote):
            db.execute("UPDATE sn_public_slots SET state='reserved',reservation_id=? WHERE slot_id=? AND state IN ('allocating','quoted')", (rid,row['slot_id']))


def reserved_inventory(db: Any, asset: str, now: int, credit_slot: str | None = None) -> int:
    if not _table_exists(db):
        return 0
    # A quoted slot is already counted by maker_quotes. Reserved funding is
    # accounted by the existing financial reservation/driver, not counted twice.
    rows = db.execute("SELECT slot_id,buy_atoms FROM sn_public_slots WHERE buy_asset=? AND expires>? AND state IN ('available','allocating')", (asset,now)).fetchall()
    return sum(atoms(amount) for slot,amount in rows if slot != credit_slot)


class PublicMarket:
    def __init__(self, store: Any, journal: Any, network: str, identity: Any):
        self.store, self.journal, self.network, self.identity = store,journal,hex32(network),identity
        with store.lock:
            apply_script(store.db, SCHEMA)

    def ingest(self, envelope: dict, now: int, *, local: bool = False) -> bool:
        body = validate_offer(envelope,self.network,now,self.identity.verify)
        raw = dumps(envelope); key = (body['provider'],body['offer_id'])
        fingerprint = digest(DOMAIN+'/RECORD',envelope)
        with self.store.transaction() as db:
            old = db.execute('SELECT sequence,record_hash FROM sn_public_sequences WHERE provider=? AND offer_id=?',key).fetchone()
            if old:
                require(body['sequence'] >= old[0], 'OFFER_REPLAY', 'Older public offer revision')
                if body['sequence'] == old[0]:
                    require(fingerprint == old[1], 'OFFER_EQUIVOCATION', 'Conflicting equal-sequence offer')
                    return False
            else:
                require(db.execute('SELECT count(*) FROM sn_public_sequences').fetchone()[0] < MAX_IDENTITIES,
                        'OFFER_IDENTITY_LIMIT', 'Public-offer replay ledger is full')
            db.execute('DELETE FROM sn_public_offers WHERE expires<=? AND local=0',(now,))
            exists = db.execute('SELECT 1 FROM sn_public_offers WHERE provider=? AND offer_id=?',key).fetchone()
            if not exists:
                require(db.execute('SELECT count(*) FROM sn_public_offers').fetchone()[0] < MAX_OFFERS,
                        'OFFER_LIMIT','Public offer catalog is full')
                require(db.execute('SELECT count(*) FROM sn_public_offers WHERE provider=?',(body['provider'],)).fetchone()[0] < MAX_PER_PROVIDER,
                        'PROVIDER_OFFER_LIMIT','Provider offer quota is full')
            db.execute('INSERT INTO sn_public_sequences VALUES(?,?,?,?,?) ON CONFLICT(provider,offer_id) DO UPDATE SET sequence=excluded.sequence,record_hash=excluded.record_hash,expires=excluded.expires',
                       (*key,body['sequence'],fingerprint,body['expires_at']))
            db.execute('INSERT INTO sn_public_offers VALUES(?,?,?,?,?,?) ON CONFLICT(provider,offer_id) DO UPDATE SET sequence=excluded.sequence,expires=excluded.expires,body=excluded.body,local=MAX(local,excluded.local)',
                       (*key,body['sequence'],body['expires_at'],raw,int(local)))
        return True

    def publish(self, policy: dict, sizes: list[str], kind: str, slots: int, ttl: int,
                inventory_atoms: str, now: int, *, offer_id: str | None = None) -> dict:
        require(kind in ('indicative','firm'),'OFFER_KIND','Choose indicative or firm')
        integer(ttl,lo=10,hi=MAX_TTL);integer(slots,lo=1,hi=MAX_SLOTS)
        require(type(sizes) is list and 1<=len(sizes)<=MAX_TIERS,'OFFER_TIERS','One to eight sizes required')
        require(len(sizes)*slots<=MAX_SLOTS,'OFFER_SLOTS','Too many capacity slots')
        market=Market(**policy['market']); inventory=atoms(inventory_atoms)
        require(now < market.expires_at,'MARKET_EXPIRED','Maker policy expired')
        oid=hex32(offer_id or secrets.token_hex(32));provider=self.identity.address()
        with self.store.lock:
            old=self.store.db.execute('SELECT body FROM sn_public_offers WHERE provider=? AND offer_id=?',(provider,oid)).fetchone()
        require(old is None,'OFFER_EXISTS','Use a new offer identifier; withdraw existing terms explicitly')
        tiers=[]
        for size in sizes:
            atoms(size,positive=True)
            tiers.append({'sell_atoms':size,'buy_atoms':str(market.output(size)),
                          'maker_fee_atoms':market.maker_fee_atoms,
                          'max_receive_network_fee_atoms':market.max_receive_network_fee_atoms,'slots':slots})
        seq=self.journal.next_sequence('public-offer:'+provider)
        body={'version':1,'network':self.network,'provider':provider,'offer_id':oid,'sequence':seq,
              'issued_at':now,'expires_at':min(now+ttl,market.expires_at),'kind':kind,
              'sell_asset':market.sell_asset,'buy_asset':market.buy_asset,'tiers':tiers,'withdrawn':False}
        # Sign before reserving, but never disseminate before both terms and
        # capacity are durable. Signing alone does not publish an offer.
        envelope={'body':body,'signature':self.identity.sign(signing_message(body))}
        validate_offer(envelope,self.network,now,self.identity.verify)
        if kind=='firm':
            with self.store.transaction() as db:
                mandate=db.execute('SELECT body,held,used,revoked FROM mandates WHERE id=?',(policy['mandate_id'],)).fetchone()
                require(mandate is not None,'MANDATE_MISSING','Maker mandate not installed')
                m=loads(mandate[0])
                require(not mandate[3] and now<m['expires_at'] and m['principal']==policy['principal'] and m['asset']==market.buy_asset,
                        'MANDATE_SCOPE','Maker mandate unavailable')
                total_inventory=sum(atoms(t['buy_atoms'])*slots for t in tiers)
                quoted=sum(atoms(r[0]) for r in db.execute('SELECT amount FROM maker_quotes WHERE asset=? AND expires>?',(market.buy_asset,now))) if db.execute("SELECT 1 FROM sqlite_master WHERE name='maker_quotes'").fetchone() else 0
                require(quoted+reserved_inventory(db,market.buy_asset,now)+total_inventory<=inventory,
                        'INSUFFICIENT_LIQUIDITY','Public capacity exceeds verified local inventory')
                fee=atoms(policy['max_local_fee_atoms'])
                require(fee<=atoms(m['max_fee_atoms']),'BUDGET_LIMIT','Maker fee cap exceeds mandate')
                debit=0
                for t in tiers:
                    payout=atoms(t['buy_atoms'])-atoms(t['maker_fee_atoms'])
                    require(payout<=atoms(m['max_trade_atoms']),'BUDGET_LIMIT','Offer exceeds per-trade mandate')
                    debit+=(payout+fee)*slots
                existing=sum(atoms(r['buy_atoms'])-atoms(r['maker_fee_atoms'])+atoms(r['fee_atoms']) for r in _live_rows(db,now,policy['mandate_id']))
                require(atoms(mandate[1])+atoms(mandate[2])+existing+debit<=atoms(m['max_total_atoms']),
                        'BUDGET_LIMIT','Offer capacity exceeds remaining mandate')
                for ti,t in enumerate(tiers):
                    for n in range(slots):
                        sid=digest(DOMAIN+'/SLOT',{'offer_id':oid,'sequence':seq,'tier':ti,'slot':n})
                        db.execute('INSERT INTO sn_public_slots VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,NULL,NULL,NULL,NULL,NULL,?)',
                                   (sid,oid,seq,ti,policy['mandate_id'],policy['principal'],market.sell_asset,market.buy_asset,
                                    t['sell_atoms'],t['buy_atoms'],t['maker_fee_atoms'],str(fee),body['expires_at'],'available',dumps(policy)))
                # Persist the signed record in this same transaction. ingest's
                # independent verification is done above; no nested transaction.
                db.execute('INSERT INTO sn_public_sequences VALUES(?,?,?,?,?)',
                           (provider,oid,seq,digest(DOMAIN+'/RECORD',envelope),body['expires_at']))
                db.execute('INSERT INTO sn_public_offers VALUES(?,?,?,?,?,1)',
                           (provider,oid,seq,body['expires_at'],dumps(envelope)))
        else:
            self.ingest(envelope,now,local=True)
        return envelope

    def get(self, provider: str, offer_id: str, now: int, *, require_live: bool = True) -> dict:
        hex32(offer_id)
        with self.store.lock:
            row=self.store.db.execute('SELECT body FROM sn_public_offers WHERE provider=? AND offer_id=?',(provider,offer_id)).fetchone()
        require(row is not None,'OFFER_MISSING','Public offer unavailable')
        env=loads(row[0]);b=env['body']
        if require_live:
            require(now<b['expires_at'] and not b['withdrawn'],'OFFER_EXPIRED','Offer is expired or withdrawn')
        return env

    def page(self, now: int, *, after: str = '', limit: int = 32,
             sell_asset: str | None = None, buy_asset: str | None = None,
             include_withdrawn: bool = False) -> dict:
        integer(limit,lo=1,hi=100)
        require(type(after) is str and len(after)<=600,'CURSOR','Invalid catalog cursor')
        rows=[]
        with self.store.lock:
            raw=self.store.db.execute('SELECT provider,offer_id,body FROM sn_public_offers WHERE expires>? ORDER BY provider,offer_id',(now,)).fetchall()
        for provider,oid,data in raw:
            key=provider+'|'+oid
            if key<=after:continue
            env=loads(data);b=env['body']
            if not include_withdrawn and b['withdrawn']:continue
            if sell_asset is not None and b['sell_asset']!=sell_asset:continue
            if buy_asset is not None and b['buy_asset']!=buy_asset:continue
            rows.append((key,env))
            if len(rows)>limit:break
        selected=rows[:limit]
        return {'offers':[x[1] for x in selected],
                'next_cursor':selected[-1][0] if len(rows)>limit else None,
                'liquidity_guaranteed':False,'capacity_evidence':'maker-local reservation, not proof of reserves'}

    def allocate(self, offer_id: str, sequence: int, tier_index: int, rfq: dict,
                 sender: str, now: int) -> tuple[dict,str | None]:
        env=self.get(self.identity.address(),offer_id,now);b=env['body']
        require(sequence==b['sequence'],'OFFER_CHANGED','Request names an obsolete offer revision')
        integer(tier_index,lo=0,hi=len(b['tiers'])-1);t=b['tiers'][tier_index]
        require((rfq['sell_asset'],rfq['buy_asset'],rfq['sell_atoms'])==(b['sell_asset'],b['buy_asset'],t['sell_atoms']),
                'OFFER_BINDING','Requested pair or size differs from public terms')
        if b['kind']=='indicative':return env,None
        rid=digest('BTX/SWAPNET/RFQ/1',rfq)
        with self.store.transaction() as db:
            old=db.execute('SELECT slot_id,requester FROM sn_public_slots WHERE rfq_id=?',(rid,)).fetchone()
            if old:
                require(old[1]==sender,'OFFER_BINDING','Allocation belongs to another requester')
                return env,old[0]
            row=db.execute("SELECT slot_id FROM sn_public_slots WHERE offer_id=? AND sequence=? AND tier=? AND state='available' AND expires>? ORDER BY slot_id LIMIT 1",(offer_id,sequence,tier_index,now)).fetchone()
            require(row is not None,'OFFER_CAPACITY','Firm offer has no unallocated capacity')
            db.execute("UPDATE sn_public_slots SET state='allocating',rfq_id=?,requester=? WHERE slot_id=?",(rid,sender,row[0]))
        return env,row[0]

    def bind_quote(self, slot_id: str, quote: Quote, now: int) -> None:
        with self.store.transaction() as db:
            row=db.execute('SELECT state,quote_id,sell_asset,buy_asset,sell_atoms,buy_atoms,maker_fee_atoms FROM sn_public_slots WHERE slot_id=?',(slot_id,)).fetchone()
            require(row and row[0] in ('allocating','quoted'),'OFFER_ALLOCATION','Allocation is unavailable')
            require(row[1] in (None,quote.id),'OFFER_ALLOCATION','Allocation already bound to another quote')
            require(tuple(row[2:])==(quote.sell_asset,quote.buy_asset,quote.sell_atoms,quote.buy_atoms,quote.maker_fee_atoms),
                    'OFFER_BINDING','Executable quote differs from reserved offer')
            db.execute("UPDATE sn_public_slots SET state='quoted',quote_id=?,nonce=?,expires=? WHERE slot_id=?",
                       (quote.id,quote.nonce,quote.expires_at,slot_id))

    def policy_for_slot(self, slot_id: str) -> dict:
        with self.store.lock:
            row=self.store.db.execute('SELECT policy FROM sn_public_slots WHERE slot_id=?',(slot_id,)).fetchone()
        require(row is not None,'OFFER_ALLOCATION','Unknown capacity slot')
        return loads(row[0])

    def policy_for_quote(self, quote_id: str) -> dict | None:
        with self.store.lock:
            row=self.store.db.execute("SELECT policy FROM sn_public_slots WHERE quote_id=? AND state IN ('quoted','reserved')",(quote_id,)).fetchone()
        return loads(row[0]) if row else None

    def withdraw(self, offer_id: str, now: int) -> dict:
        old=self.get(self.identity.address(),offer_id,now,require_live=False);body=dict(old['body'])
        body.update(sequence=self.journal.next_sequence('public-offer:'+body['provider']),
                    issued_at=now,expires_at=now+MAX_TTL,withdrawn=True)
        envelope={'body':body,'signature':self.identity.sign(signing_message(body))}
        self.ingest(envelope,now,local=True)
        with self.store.transaction() as db:
            # Requester-bound quotes and already signed agreements retain their
            # original commitments; withdrawal releases only unallocated slots.
            db.execute("UPDATE sn_public_slots SET state='withdrawn' WHERE offer_id=? AND state='available'",(offer_id,))
        return envelope

    def close_expired(self, now: int) -> None:
        with self.store.transaction() as db:
            db.execute("UPDATE sn_public_slots SET state='expired' WHERE expires<=? AND state IN ('available','allocating','quoted')",(now,))
            db.execute('DELETE FROM sn_public_requests WHERE expires<?',(now-MAX_TTL,))
            db.execute('DELETE FROM sn_market_refusals WHERE observed<?',(now-86400*7,))
            db.execute('DELETE FROM sn_public_offers WHERE expires<?',(now-MAX_TTL,))
            # A watermark outlives every record it can reject. Removing it only
            # after the maximum valid lifetime cannot resurrect an old record.
            db.execute('DELETE FROM sn_public_sequences WHERE expires<?',(now-MAX_TTL,))

    def local_capacity(self, now: int) -> dict:
        with self.store.lock:
            rows=self.store.db.execute('SELECT offer_id,tier,state,count(*) FROM sn_public_slots WHERE expires>? GROUP BY offer_id,tier,state',(now,)).fetchall()
        return {'slots':[{'offer_id':o,'tier':t,'state':s,'count':n} for o,t,s,n in rows],
                'scope':'this node only','proof_of_reserves':False}
