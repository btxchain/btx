"""Signed-proof route alternatives. Native production instances delegate to shared_p2p.

The Python table is a deterministic component-test backend. Neither backend treats
an observed relay as a financial counterparty or as a trusted source of chain data.
"""
from collections import OrderedDict
from .market_controls import require, integer

class RouteBook:
    def __init__(self, now, native=None, max_routes=8192, max_alternates=4):
        self.now, self.native = now, native
        self.max_routes, self.max_alternates = max_routes, max_alternates
        self.rows = OrderedDict()

    def _expire(self):
        now=self.now()
        for identity in list(self.rows):
            self.rows[identity]=[r for r in self.rows[identity] if r['expires']>now]
            if not self.rows[identity]:del self.rows[identity]

    def learn(self, identity, peer, expires, proof):
        integer(peer,0,(1<<53)-1,'peer')
        require(type(identity) is str and 0<len(identity)<=256,'IDENTITY','Invalid route identity')
        require(type(proof) is str and 0<len(proof)<=128,'PROOF','Invalid proof reference')
        require(0<expires-self.now()<=600,'EXPIRY','Route outside signed lifetime')
        if self.native:
            return self.native('learn',{'identity':identity,'peer':peer,'ttl_ms':(expires-self.now())*1000,'proof':proof})
        self._expire()
        if identity not in self.rows:
            if len(self.rows)>=self.max_routes:return False
            self.rows[identity]=[]
        rows=self.rows[identity]
        for row in rows:
            if row['peer']==peer:
                if row['proof']!=proof:row.update(expires=expires,proof=proof)
                return True
        if len(rows)>=self.max_alternates:return False
        rows.append({'peer':peer,'expires':expires,'proof':proof})
        return True

    def candidates(self, identity, peers, attempt=0, exclude=None):
        integer(attempt,0,(1<<53)-1,'route attempt')
        if self.native:
            rows=self.native('candidates',{'identity':identity,'attempt':attempt})['peers']
        else:
            self._expire();rows=[r['peer'] for r in self.rows.get(identity,[])]
            if rows:offset=attempt%len(rows);rows=rows[offset:]+rows[:offset]
        return [p for p in rows if p in peers and p!=exclude]

    def close(self, peer):
        if self.native:return self.native('closed',{'peer':peer})
        for identity in list(self.rows):
            self.rows[identity]=[r for r in self.rows[identity] if r['peer']!=peer]
            if not self.rows[identity]:del self.rows[identity]


def diverse_fallback(peers, attempt=0, exclude=None, limit=8):
    """Rotates coverage rather than always selecting the first eight connections.
    Connection diversity is not proof of independent operators.
    """
    eligible=sorted(p for p in peers if p!=exclude)
    if not eligible:return []
    offset=(attempt*limit)%len(eligible)
    return (eligible[offset:]+eligible[:offset])[:limit]
