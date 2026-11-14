"""Signed provider catalog over existing BTX peers; no invented seed endpoints."""
from .canonical import exact_fields, integer, hex32, dumps, loads, digest
from .assets import Asset
from .errors import require

MAX_PROVIDERS=2048
MAX_PAIRS=16

class Catalog:
    def __init__(self,store,network,verify):
        self.store,self.network,self.verify=store,hex32(network),verify

    def ingest(self,envelope,now):
        exact_fields(envelope,{'body','signature'})
        b=envelope['body']
        exact_fields(b,{'version','network','identity','sequence','issued_at','expires_at','pairs','settlement'})
        require(b['version'] == 1 and type(b['version']) is int,"VERSION","Unsupported provider version")
        require(b['network'] == self.network,"NETWORK","Provider belongs to a different BTX network")
        require(type(b['identity']) is str and 1 <= len(b['identity']) <= 256,"IDENTITY","Invalid provider identity")
        integer(b['sequence'],lo=1); integer(b['issued_at']); integer(b['expires_at'])
        require(b['issued_at'] <= now < b['expires_at'] <= b['issued_at']+600,"ADVERTISEMENT_TTL","Advertisement stale or future-dated")
        require(b['settlement'] == ['sha256-htlc-v1'],"SETTLEMENT","Unknown settlement protocol")
        require(type(b['pairs']) is list and 0 < len(b['pairs']) <= MAX_PAIRS,"PAIRS","Invalid pair list")
        unique=set()
        for pair in b['pairs']:
            exact_fields(pair,{'sell','buy'})
            Asset.parse(pair['sell']); Asset.parse(pair['buy'])
            require(pair['sell'] != pair['buy'],"PAIR","Identical assets")
            key=(pair['sell'],pair['buy'])
            require(key not in unique,"PAIR","Duplicate pair")
            unique.add(key)
        msg='BTX/SWAPNET/PROVIDER/1:'+digest('BTX/SWAPNET/PROVIDER/1',b)
        sig=envelope['signature']
        require(type(sig) is str and 1 <= len(sig) <= 16384,"SIGNATURE","Invalid provider signature")
        require(self.verify(b['identity'],sig,msg) is True,"BAD_SIGNATURE","Provider signature rejected")
        raw=dumps(envelope)
        with self.store.transaction() as db:
            row=db.execute('SELECT sequence FROM peer_sequences WHERE identity=?',(b['identity'],)).fetchone()
            require(row is None or b['sequence'] > row[0],"REPLAY","Provider sequence did not increase")
            db.execute('DELETE FROM providers WHERE expires<=?',(now,))
            exists=db.execute('SELECT 1 FROM providers WHERE identity=?',(b['identity'],)).fetchone()
            count=db.execute('SELECT COUNT(*) FROM providers').fetchone()[0]
            require(exists or count < MAX_PROVIDERS,"CATALOG_FULL","Provider cache full")
            # Sequence table is bounded too; refusing new identities beats unbounded Sybil growth.
            if row is None:
                require(db.execute('SELECT COUNT(*) FROM peer_sequences').fetchone()[0] < MAX_PROVIDERS*4,
                        "IDENTITY_LIMIT","Persistent identity limit reached")
            db.execute('INSERT INTO peer_sequences VALUES(?,?) ON CONFLICT(identity) DO UPDATE SET sequence=excluded.sequence',(b['identity'],b['sequence']))
            db.execute('INSERT INTO providers VALUES(?,?,?) ON CONFLICT(identity) DO UPDATE SET expires=excluded.expires,body=excluded.body',(b['identity'],b['expires_at'],raw))
        return b['identity']

    def search(self,now,sell=None,buy=None,after='',limit=50):
        integer(limit,lo=1,hi=100)
        if sell is not None: Asset.parse(sell)
        if buy is not None: Asset.parse(buy)
        with self.store.lock:
            rows=self.store.db.execute('SELECT identity,body FROM providers WHERE expires>? AND identity>? ORDER BY identity',(now,after)).fetchall()
        result=[]
        for identity,raw in rows:
            env=loads(raw)
            if any((sell is None or p['sell']==sell) and (buy is None or p['buy']==buy) for p in env['body']['pairs']):
                result.append(env)
                if len(result)==limit: break
        return {'providers':result,'next_cursor':result[-1]['body']['identity'] if len(result)==limit else None,
                'liquidity_guaranteed':False}
