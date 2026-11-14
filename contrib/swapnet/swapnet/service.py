"""Authenticated local coordinator RPCs. Peer inputs have NO owner capabilities.

This is an executable application layer, not a claim that btxd native lifecycle
and the hardware/wallet authority broker have already been wired. Unsupported
live execution is explicitly rejected rather than simulated as successful.
"""
from dataclasses import dataclass,asdict
import time
from .canonical import atoms,hex32,dumps,loads,integer,digest,exact_fields
from .policy import Mandate
from .quote import Quote,SignedQuote,rank_quotes
from .discovery import Catalog
from .machine import Session
from .errors import SwapError,require

METHODS={
 'getswapnetworkinfo':'read', 'listswapassets':'read', 'listswapproviders':'read',
 'searchswaps':'read', 'requestswapquote':'quote', 'getswapquotes':'read',
 'acceptswapquote':'trade', 'listswaps':'read', 'getswap':'read',
 'cancelswap':'trade','getswaptranscript':'audit', 'listswapmandates':'read',
 'createswapmandate':'owner','revokeswapmandate':'owner',
 'getswapcapabilities':'read','resumeswap':'trade','refundswap':'trade',
 'listswapoperations':'audit', 'getswaphealth':'read',
 'publishswapprovider':'maker','withdrawswapprovider':'maker',
 'getswapbootstrapinfo':'read','getswaprecoveryinfo':'read'
}

@dataclass(frozen=True)
class Context:
    principal:str
    capabilities:frozenset
    # Constructed by the native authenticated IPC/RPC broker, NEVER from JSON.

class Service:
    def __init__(self,store,network,verify_identity,*,clock=None,enqueue=None,assets=(),authority=None):
        self.store=store;self.network=hex32(network);self.verify=verify_identity
        self.clock=clock or (lambda:int(time.time()));self.enqueue=enqueue
        self.catalog=Catalog(store,network,verify_identity)
        self.assets=list(assets);self.authority=authority
        with store.transaction() as db:
            db.execute('CREATE TABLE IF NOT EXISTS quotes(id TEXT PRIMARY KEY,expires INTEGER NOT NULL,body BLOB NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS rfqs(id TEXT PRIMARY KEY,expires INTEGER NOT NULL,principal TEXT NOT NULL,body BLOB NOT NULL)')
    def _scope(self,ctx,method):
        require(isinstance(ctx,Context),'AUTH','Authenticated context required')
        needed=METHODS.get(method)
        require(needed is not None,'METHOD_NOT_FOUND','Unknown SwapNet RPC')
        require(needed in ctx.capabilities,'FORBIDDEN','Capability not granted')
    def dispatch(self,ctx,method,params=None):
        self._scope(ctx,method);p=params or {};require(type(p) is dict,'PARAMS','Named object parameters required')
        fn=getattr(self,'rpc_'+method)
        try:return fn(ctx,**p)
        except TypeError as e:raise SwapError('PARAMS','Unexpected or missing argument') from e
    def _session(self,ctx,sid):
        rev,body=self.store.load_session(hex32(sid))
        require(body.get('principal')==ctx.principal,'FORBIDDEN','Swap belongs to another principal')
        return rev,body
    def rpc_getswapnetworkinfo(self,ctx):
        with self.store.lock:n=self.store.db.execute('SELECT COUNT(*) FROM providers WHERE expires>?',(self.clock(),)).fetchone()[0]
        return {'protocol':1,'discovery_default':True,'automatic_spend_atoms':'0',
                'network':self.network,'providers':n,'native_transport_attached':self.enqueue is not None,
                'funding_authority_attached':self.authority is not None,
                'release_qualified':False,'mode':'integration_candidate'}
    def rpc_getswapcapabilities(self,ctx):
        return {'methods':[{'name':m,'scope':s} for m,s in METHODS.items()],
                'settlement':['sha256-htlc-v1'],'partial_fills':False,'multihop':False}
    def rpc_listswapassets(self,ctx):return {'assets':self.assets,'unknown_assets_enabled':False}
    def rpc_listswapproviders(self,ctx,sell=None,buy=None,after='',limit=50):return self.catalog.search(self.clock(),sell,buy,after,limit)
    def rpc_searchswaps(self,ctx,sell=None,buy=None,after='',limit=50):return self.rpc_listswapproviders(ctx,sell,buy,after,limit)
    def rpc_requestswapquote(self,ctx,sell_asset,buy_asset,sell_atoms,nonce):
        from .assets import Asset
        Asset.parse(sell_asset);Asset.parse(buy_asset);atoms(sell_atoms,positive=True);hex32(nonce)
        require(sell_asset!=buy_asset,'PAIR','Different assets required')
        now=self.clock();requester=digest('BTX/SWAPNET/REQUESTER/1',{'principal':ctx.principal,'nonce':nonce})
        b={'network':self.network,'requester':requester,'sell_asset':sell_asset,'buy_asset':buy_asset,
           'sell_atoms':sell_atoms,'nonce':nonce,'issued_at':now,'expires_at':now+120}
        rid=digest('BTX/SWAPNET/RFQ/1',b)
        require(self.enqueue is not None,'NO_TRANSPORT','Native peer transport is not attached')
        with self.store.transaction() as db:
            db.execute('DELETE FROM rfqs WHERE expires<=?',(now,))
            require(db.execute('SELECT COUNT(*) FROM rfqs').fetchone()[0]<256,'RFQ_LIMIT','Too many RFQs')
            db.execute('INSERT OR IGNORE INTO rfqs VALUES(?,?,?,?)',(rid,now+120,ctx.principal,dumps(b)))
        # Transport failure leaves request discoverable and retryable, not funded.
        self.enqueue('swrfq',b)
        return {'request_id':rid,'requester':requester,'expires_at':now+120}
    def ingest_quote(self,env,request_id):
        exact_fields(env,{'quote','signature'});sq=SignedQuote(Quote.parse(env['quote']),env['signature'])
        now=self.clock()
        with self.store.lock:row=self.store.db.execute('SELECT body FROM rfqs WHERE id=? AND expires>?',(request_id,now)).fetchone()
        require(row is not None,'RFQ_MISSING','No matching live request')
        rfq=loads(row[0]);q=sq.verify(self.verify,self.network,rfq['requester'],now)
        require((q.sell_asset,q.buy_asset,q.sell_atoms)==(rfq['sell_asset'],rfq['buy_asset'],rfq['sell_atoms']),
                'QUOTE_BINDING','Quote changed requested pair or size')
        with self.store.transaction() as db:
            db.execute('DELETE FROM quotes WHERE expires<=?',(now,))
            require(db.execute('SELECT COUNT(*) FROM quotes').fetchone()[0]<1024,'QUOTE_LIMIT','Quote cache full')
            db.execute('INSERT OR IGNORE INTO quotes VALUES(?,?,?)',(q.id,q.expires_at,dumps(env)))
        return q.id
    def rpc_getswapquotes(self,ctx,request_id):
        with self.store.lock:
            row=self.store.db.execute('SELECT body,principal FROM rfqs WHERE id=?',(request_id,)).fetchone()
            require(row is not None and row[1]==ctx.principal,'FORBIDDEN','RFQ unavailable')
            rfq=loads(row[0]);rows=self.store.db.execute('SELECT body FROM quotes WHERE expires>?',(self.clock(),)).fetchall()
        qs=[Quote.parse(loads(r[0])['quote']) for r in rows]
        qs=[q for q in qs if q.requester==rfq['requester']]
        ranked=rank_quotes(qs,rfq['sell_asset'],rfq['buy_asset'],rfq['sell_atoms'],self.clock())
        return {'quotes':[{'id':q.id,**asdict(q),'minimum_receive_atoms':str(q.net_buy)} for q in ranked]}
    def rpc_createswapmandate(self,ctx,mandate):
        exact_fields(mandate,Mandate.__dataclass_fields__)
        m=Mandate(**mandate)
        return {'mandate_id':self.store.install_mandate(m,owner_authorized=True)}
    def rpc_revokeswapmandate(self,ctx,mandate_id):
        self.store.revoke(hex32(mandate_id),owner_authorized=True);return {'revoked':True,'recovery_preserved':True}
    def rpc_listswapmandates(self,ctx):
        with self.store.lock:rows=self.store.db.execute('SELECT id,body,held,used,revoked FROM mandates').fetchall()
        return {'mandates':[{'id':r[0],'mandate':loads(r[1]),'held_atoms':r[2],'used_atoms':r[3],'revoked':bool(r[4])}
                            for r in rows if loads(r[1])['principal']==ctx.principal]}
    def rpc_acceptswapquote(self,ctx,quote_id,mandate_id,max_local_fee_atoms):
        with self.store.lock:row=self.store.db.execute('SELECT body FROM quotes WHERE id=?',(hex32(quote_id),)).fetchone()
        require(row is not None,'QUOTE_MISSING','Quote unavailable')
        env=loads(row[0]);q=Quote.parse(env['quote'])
        with self.store.lock:rfqs=self.store.db.execute('SELECT body FROM rfqs WHERE principal=?',(ctx.principal,)).fetchall()
        require(any(loads(r[0])['requester']==q.requester for r in rfqs),'FORBIDDEN','Quote belongs to another requester')
        SignedQuote(q,env['signature']).verify(self.verify,self.network,q.requester,self.clock())
        rid=self.store.reserve(q,hex32(mandate_id),ctx.principal,max_local_fee_atoms,self.clock())
        sid=digest('BTX/SWAPNET/SESSION/1',{'reservation_id':rid})
        # Separate writes are intentional: restart can recover the reserved quote
        # by rerunning this idempotent acceptance. No funding occurs between them.
        try:_,body=self.store.load_session(sid)
        except SwapError as e:
            if e.code!='NOT_FOUND':raise
            state=Session(sid,'initiator');state.authorize()
            body={'id':sid,'principal':ctx.principal,'reservation_id':rid,'quote_id':q.id,
                  'state':state.export(),'execution':'awaiting_signed_agreement'}
            try:self.store.save_session(sid,body)
            except SwapError as save:
                if save.code!='REVISION_CONFLICT':raise
                _,body=self.store.load_session(sid)
        return body
    def rpc_listswaps(self,ctx,limit=100):
        return {'swaps':[s for s in self.store.list_sessions(limit) if s.get('principal')==ctx.principal]}
    def rpc_getswap(self,ctx,swap_id):return self._session(ctx,swap_id)[1]
    def rpc_cancelswap(self,ctx,swap_id):
        return self.store.cancel_session(hex32(swap_id),ctx.principal)
    def rpc_getswaptranscript(self,ctx,swap_id):
        _,b=self._session(ctx,swap_id)
        return {'swap':b,'audit_head':self.store.verify_audit(),'secrets_included':False}
    def rpc_listswapoperations(self,ctx,swap_id):
        self._session(ctx,swap_id)
        # Raw signed claims may contain a secret. Never expose operation bodies
        # through a generic read-only RPC. Scoped native receipts are future glue.
        return {'available':False,'reason':'native_receipt_scope_not_attached'}
    def _execute(self,ctx,swap_id,action):
        _,b=self._session(ctx,swap_id)
        require(self.authority is not None,'NATIVE_AUTHORITY_REQUIRED','Live execution requires the scoped native wallet/chain broker')
        return self.authority(action,b,ctx)
    def rpc_resumeswap(self,ctx,swap_id):return self._execute(ctx,swap_id,'resume')
    def rpc_refundswap(self,ctx,swap_id):return self._execute(ctx,swap_id,'refund')
    def rpc_getswaphealth(self,ctx):return {'database_audit':self.store.verify_audit(),'release_qualified':False}
    def rpc_getswapbootstrapinfo(self,ctx):
        return {'mechanism':'existing_btx_peers','separate_seeds':False,'attached':self.enqueue is not None,
                'empty_network_is_error':False,'fabricated_liquidity':False}
    def rpc_getswaprecoveryinfo(self,ctx,swap_id):
        _,b=self._session(ctx,swap_id)
        return {'swap_id':swap_id,'durable_recovery_ready':b['state']['recovery_ready'],
                'secret_exposed':b['state']['secret_exposed'],'raw_transactions_redacted':True}
    def rpc_publishswapprovider(self,ctx,envelope):
        require(envelope.get('body',{}).get('identity')==ctx.principal,'FORBIDDEN','Provider identity differs from authenticated principal')
        require(self.enqueue is not None,'NO_TRANSPORT','Native transport absent')
        identity=self.catalog.ingest(envelope,self.clock());self.enqueue('swprov',envelope)
        return {'identity':identity,'advertised':True,'proof_of_reserves':False}
    def rpc_withdrawswapprovider(self,ctx):
        with self.store.transaction() as db:db.execute('DELETE FROM providers WHERE identity=?',(ctx.principal,))
        return {'local_removed':True,'remote_expires_within_seconds':600}
