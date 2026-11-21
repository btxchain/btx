"""Native application extension. Uses existing authority, coordinator and chain drivers.

No alternative signing, custody, settlement or consensus implementation lives here.
New methods are registered by the integration patch in the native RPC catalog.
"""
from dataclasses import asdict
import hashlib
import json
from collections import OrderedDict
from .market_controls import (ExecutionPolicy, MakerPolicy, ControlError, amount,
                              evaluate_quote, fingerprint, require)
from .lifecycle import ModeControl
from .quote_preview import PreviewStore
from .routing_v3 import RouteBook, diverse_fallback
from .transparency import local_market_health, settlement_receipt
from .quote import Quote
from .policy import Mandate
from .authorization import Principal
from .canonical import dumps, loads, digest, atoms
from .errors import SwapError

LIQUIDITY_METHODS={
 'getswapmode':'read','setswapmode':'owner','getswaponboarding':'read',
 'getswapexecutionpolicy':'read','setswapexecutionpolicy':'owner',
 'previewswapquote':'trade','confirmswapquote':'trade',
 'setswapmakerpolicy':'owner','getswapmakerpolicies':'owner',
 'getswapmarkethealth':'owner','exportswapreceipt':'audit',
 'getswappeercoreinfo':'read','setupswapbitcoin':'owner'}

class LiquidityApplicationMixin:
    def _liquidity_init(self,initial_mode='observe',route_backend=None,client_version=None):
        self._modes=ModeControl(self.journal,initial_mode)
        self._preview=PreviewStore(self.store,self.now)
        self._route_book=RouteBook(self.now,native=route_backend)
        self._route_attempts=OrderedDict()
        from .catalog_pager import CatalogPager
        self._catalog_pager=CatalogPager(self.now)
        self._native_route_backend=route_backend
        self._client_version=client_version if type(client_version) is str and len(client_version)<=256 else None
        self.coordinator.new_taker_guard=self._modes.permit_new_taker
        self.coordinator.new_maker_guard=self._modes.permit_new_maker
        self.coordinator.maker_quote_validator=self._liquidity_validate_maker_quote
        with self.store.transaction() as db:
            db.execute('CREATE TABLE IF NOT EXISTS sn_maker_quote_policy(quote_id TEXT PRIMARY KEY,peer TEXT NOT NULL,expires INTEGER NOT NULL,policy_digest TEXT NOT NULL)')

    def _execution_policy(self):
        return ExecutionPolicy.parse(self.journal.setting('liquidity_execution_policy',{}))

    def rpc_getswapmode(self,ctx):return self._modes.status()
    def rpc_setswapmode(self,ctx,mode):
        self.authority.owner(ctx)
        result=self._modes.set(mode)
        if mode!='maker':self.journal.set_setting('own_advertisement',None)
        # Advertisement expiry is not a cancellation of a funded trade.
        result['remote_advertisements_expire_within_seconds']=600
        return result
    def rpc_getswapexecutionpolicy(self,ctx):
        p=self._execution_policy()
        return {'policy':p.document(),'digest':p.digest,'references_are_owner_selected':True}
    def rpc_setswapexecutionpolicy(self,ctx,policy):
        self.authority.owner(ctx);p=ExecutionPolicy.parse(policy)
        self.journal.set_setting('liquidity_execution_policy',p.document())
        return {'policy':p.document(),'digest':p.digest}

    def _owned_quote(self,ctx,quote_id):
        with self.store.lock:
            row=self.store.db.execute('SELECT body FROM quotes WHERE id=?',(quote_id,)).fetchone()
            requests=self.store.db.execute('SELECT body FROM rfqs WHERE principal=?',(ctx.name,)).fetchall()
        require(row is not None,'QUOTE_MISSING','Quote unavailable')
        env=loads(row[0]);q=Quote.parse(env['quote'])
        rfqs=[loads(r[0]) for r in requests]
        rfq=next((r for r in rfqs if r['requester']==q.requester and
                  (r['sell_asset'],r['buy_asset'],r['sell_atoms'])==(q.sell_asset,q.buy_asset,q.sell_atoms)),None)
        require(rfq is not None,'FORBIDDEN','Quote belongs to another caller')
        return q,env,rfq

    def _decision(self,ctx,q,rfq):
        request_id=digest('BTX/SWAPNET/RFQ/1',rfq)
        candidates=self.service.rpc_getswapquotes(self._context(ctx),request_id)['quotes']
        return evaluate_quote(asdict(q),candidates,self._execution_policy(),self.now())

    def _guard_accept(self,ctx,quote_id):
        q,env,rfq=self._owned_quote(ctx,quote_id)
        sid=digest('BTX/SWAPNET/SWAP/2',{'quote_id':q.id,'initiator':self._identity()})
        try:
            _,old=self.coordinator._owned(ctx,sid)
        except SwapError as e:
            if e.code!='NOT_FOUND':raise
        else:
            return # Idempotent queries/recovery retain original authority; not a new trade.
        self._modes.permit_new_taker()
        decision=self._decision(ctx,q,rfq)
        require(decision['allowed'],'EXECUTION_POLICY',','.join(decision['reasons']))

    def rpc_previewswapquote(self,ctx,quote_id,max_local_fee_atoms,refund_fee_atoms=None,claim_fee_atoms=None):
        q,env,rfq=self._owned_quote(ctx,quote_id)
        cap=amount(max_local_fee_atoms,positive=True)
        refund_fee_atoms=refund_fee_atoms or str(cap//2)
        claim_fee_atoms=claim_fee_atoms or q.max_receive_network_fee_atoms
        require(amount(refund_fee_atoms)<=cap,'FEE_CAP','Refund cap exceeds outgoing budget')
        require(amount(claim_fee_atoms)<=amount(q.max_receive_network_fee_atoms),'FEE_CAP','Claim cap exceeds signed quote')
        decision=self._decision(ctx,q,rfq)
        parameters={'quote_id':q.id,'max_local_fee_atoms':max_local_fee_atoms,
                    'refund_fee_atoms':refund_fee_atoms,'claim_fee_atoms':claim_fee_atoms}
        pid,body=self._preview.create(ctx.name,ctx.wallet,asdict(q),parameters,decision['policy_digest'])
        return {'preview_id':pid,'expires_at':body['expires_at'],'quote':asdict(q),'decision':decision,
                'outgoing_fee_cap':{'asset':q.sell_asset,'atoms':max_local_fee_atoms},
                'minimum_receive':{'asset':q.buy_asset,'atoms':str(q.net_buy)},
                'mode':self._modes.status(),'spending_authorized':False,
                'single_trade_authorization_expires_at':body['created_at']+600,
                'disclosures':['Settlement requires both chain verifiers and fees.',
                    'The counterparty can decline to fund; recovery can require waiting for the HTLC deadline.',
                    'Quote coverage counts signing identities, not proven independent owners.']}

    def rpc_confirmswapquote(self,ctx,preview_id,consent,mandate_id=None,create_single_trade_mandate=False):
        require(consent is True,'CONSENT','Explicit confirmation is required')
        require(type(create_single_trade_mandate) is bool,'CONSENT','Invalid mandate choice')
        body,done=self._preview.read(preview_id,ctx.name,ctx.wallet)
        if done:return self.coordinator.get(ctx,done)
        q=Quote.parse(body['quote']);params=dict(body['parameters'])
        sid=digest('BTX/SWAPNET/SWAP/2',{'quote_id':q.id,'initiator':self._identity()})
        try:
            _,existing=self.coordinator._owned(ctx,sid)
        except SwapError as e:
            if e.code!='NOT_FOUND':raise
        else:
            self._preview.complete(preview_id,ctx.name,ctx.wallet,sid)
            return self.coordinator.get(ctx,sid)
        require(self.now()<body['expires_at'],'PREVIEW_EXPIRED','Obtain a new preview')
        require(self._execution_policy().digest==body['policy_digest'],'POLICY_CHANGED','Execution policy changed after preview')
        self._guard_accept(ctx,q.id)
        if create_single_trade_mandate:
            self.authority.owner(ctx)
            require(mandate_id is None,'MANDATE','Choose an existing mandate or a new single-trade mandate')
            fee=params['max_local_fee_atoms'];total=amount(q.sell_atoms)+amount(fee)
            require(total<=(1<<256)-1,'BUDGET_LIMIT','Combined authorization exceeds range')
            m=Mandate(principal=ctx.name,asset=q.sell_asset,max_total_atoms=str(total),
                      max_trade_atoms=q.sell_atoms,max_fee_atoms=fee,expires_at=body['created_at']+600,
                      nonce=hashlib.sha256(('BTX/SWAPNET/PREVIEW-MANDATE/1:'+preview_id).encode()).hexdigest())
            with self.store.lock:exists=self.store.db.execute('SELECT 1 FROM mandates WHERE id=?',(m.id,)).fetchone()
            if not exists:self.authority.install(ctx,asdict(m))
            mandate_id=m.id
        require(type(mandate_id) is str and len(mandate_id)==64,'MANDATE_REQUIRED','A bounded owner-issued mandate is required')
        result=self.rpc_acceptswapquote(ctx,mandate_id=mandate_id,**params)
        self._preview.complete(preview_id,ctx.name,ctx.wallet,sid)
        return result

    def rpc_getswaponboarding(self,ctx):
        # Readiness is separate from automatic setup or signing. Never calls a wallet RPC.
        info=self.rpc_getswapnetworkinfo(ctx)
        assets=[]
        for asset,d in self.drivers.items():
            assets.append({'asset':asset,'family':d.family,'driver_configured':True,
                           'financial_readiness':'not_asserted_by_discovery',
                           'verification_requirement':'owner-operated chain verifier; no peer-supplied RPC'})
        return {'mode':self._modes.status(),'network':self.network,'peers':len(self.peers),
                'providers':info['providers'],'wallet_loaded':info.get('wallet_loaded'),
                'assets':assets,'setup_does_not_spend':True,
                'bitcoin_watch_wallet_must_be_separate':True,
                'evm_gas_and_verified_deployment_required':True,
                'public_liquidity_guaranteed':False}

    def _maker_policy(self,market):
        key=market['sell_asset']+'|'+market['buy_asset']
        return MakerPolicy(**self.journal.setting('liquidity_maker_policies',{}).get(key,{}))
    def rpc_setswapmakerpolicy(self,ctx,sell_asset,buy_asset,policy):
        self.authority.owner(ctx)
        from .assets import Asset
        Asset.parse(sell_asset);Asset.parse(buy_asset)
        require(sell_asset!=buy_asset,'PAIR','Different assets required')
        require(type(policy) is dict and not(set(policy)-set(MakerPolicy.__dataclass_fields__)),'POLICY','Unknown maker policy field')
        p=MakerPolicy(**policy);policies=self.journal.setting('liquidity_maker_policies',{})
        key=sell_asset+'|'+buy_asset
        require(key in policies or len(policies)<16,'MARKET_LIMIT','At most 16 maker policies')
        policies[key]=asdict(p);self.journal.set_setting('liquidity_maker_policies',policies)
        return {'policy':asdict(p),'advertisements_are_not_proof_of_reserves':True}
    def rpc_getswapmakerpolicies(self,ctx):
        self.authority.owner(ctx);return {'policies':self.journal.setting('liquidity_maker_policies',{})}
    def _liquidity_market(self,policy,rfq,sender):
        from .marketmaker import Market
        self._modes.permit_new_maker()
        m=policy['market'];p=self._maker_policy(m)
        driver=self.coordinator._driver(m['buy_asset']);inventory=int(driver.inventory())
        require(inventory>=0,'INVENTORY','Invalid local inventory')
        effective=p.quote_terms(m,str(inventory))
        require(amount(rfq['sell_atoms'])>=amount(p.effective_minimum(effective)),'MARKET_MINIMUM','Trade is below the fee-aware maker minimum')
        self.coordinator.check_finality(self.coordinator._driver(m['sell_asset']),driver)
        with self.store.transaction() as db:
            db.execute('DELETE FROM sn_maker_quote_policy WHERE expires<=?',(self.now(),))
            require(db.execute('SELECT COUNT(*) FROM sn_maker_quote_policy WHERE peer=?',(sender,)).fetchone()[0]<p.max_quotes_per_requester,
                    'REQUESTER_LIMIT','Too many outstanding quotes from this signing identity')
        return Market(**effective),max(0,inventory-amount(p.inventory_floor_atoms))
    def _liquidity_note_quote(self,q,policy,sender):
        pd=fingerprint({'market':policy['market'],'strategy':asdict(self._maker_policy(policy['market']))})
        with self.store.transaction() as db:
            db.execute('DELETE FROM sn_maker_quote_policy WHERE expires<=?',(self.now(),))
            require(db.execute('SELECT COUNT(*) FROM sn_maker_quote_policy').fetchone()[0]<1024,'QUOTE_LIMIT','Maker quote policy cache full')
            db.execute('INSERT OR IGNORE INTO sn_maker_quote_policy VALUES(?,?,?,?)',(q.id,sender,q.expires_at,pd))
    def _liquidity_validate_maker_quote(self,q,policy):
        from .marketmaker import Market
        pd=fingerprint({'market':policy['market'],'strategy':asdict(self._maker_policy(policy['market']))})
        with self.store.lock:
            row=self.store.db.execute('SELECT policy_digest,expires FROM sn_maker_quote_policy WHERE quote_id=?',(q.id,)).fetchone()
            issued=self.store.db.execute('SELECT body FROM maker_quotes WHERE expires>?',(self.now(),)).fetchall()
        if row:
            require(row[0]==pd and self.now()<row[1],'MARKET_POLICY_CHANGED','Maker policy changed or expired after quoting')
            require(any(Quote.parse(loads(r[0])).id==q.id for r in issued),'QUOTE_NOT_ISSUED','Quote is not in the local issued-quote ledger')
        else:
            # Legacy in-flight static quotes remain compatible; no dynamic price acceptance without a record.
            pricing=Market(**policy['market'])
            require(pricing.output(q.sell_atoms)==atoms(q.buy_atoms) and pricing.maker_fee_atoms==q.maker_fee_atoms,
                    'MARKET_PRICE','Quoted price is not currently authorized')

    def rpc_getswapmarkethealth(self,ctx,after='',limit=1024):
        self.authority.owner(ctx)
        require(type(after) is str and len(after)<=64 and type(limit) is int and 1<=limit<=4096,'HISTORY_LIMIT','Invalid bounded history page')
        last=[after];count=[0]
        with self.store.lock:
            cursor=self.store.db.execute('SELECT id,body FROM sn_negotiations WHERE id>? ORDER BY id LIMIT ?',(after,limit))
            def rows():
                for sid,raw in cursor:
                    last[0]=sid;count[0]+=1
                    yield sid,0,json.loads(raw)
            result=local_market_health(rows())
            more=self.store.db.execute('SELECT 1 FROM sn_negotiations WHERE id>? LIMIT 1',(last[0],)).fetchone()
        return {**result,'coverage':'bounded_local_history_page','rows':count[0],
                'next_cursor':last[0] if more else None,'concentration_is_page_specific':True}
    def rpc_exportswapreceipt(self,ctx,swap_id,consent=False):
        require(consent is True,'CONSENT','Receipt export discloses public trade links; explicit consent required')
        _,s=self.coordinator._owned(ctx,swap_id)
        return settlement_receipt(swap_id,s)
    def rpc_getswappeercoreinfo(self,ctx):
        if self._native_route_backend:
            result=self._native_route_backend('status',{})
        else:result={'backend':'component-test-python','routes':len(self._route_book.rows)}
        return {**result,'scope':'local_process','shared_services':result.get('registered_services',{}),
                'pq1_not_downgraded':True,'routing_is_not_economic_multihop':True}

    def _liquidity_route(self,recipient,command,packet,hops=4,exclude=None):
        now=self.now()
        for key,(_,expiry) in list(self._route_attempts.items()):
            if expiry<=now:self._route_attempts.pop(key,None)
        mid=digest('BTX/SWAPNET/ROUTE-ATTEMPT/1',packet)
        attempt=self._route_attempts.get(mid,(0,0))[0]
        if mid not in self._route_attempts and len(self._route_attempts)>=4096:self._route_attempts.popitem(last=False)
        self._route_attempts[mid]=(attempt+1,packet['body']['expires_at'])
        raw=dumps({'packet':packet,'hops':hops}).decode()
        candidates=self._route_book.candidates(recipient,self.peers,attempt,exclude) if recipient!='*' else []
        # A successful enqueue is NOT a remote acknowledgement. Retry eventually explores alternatives/floods.
        if candidates and attempt<len(candidates):
            for peer in candidates:
                if self.send(peer,command,raw):return True
        sent=False
        for peer in diverse_fallback(self.peers,attempt,exclude):sent=bool(self.send(peer,command,raw)) or sent
        return sent

    def rpc_setupswapbitcoin(self,ctx,wallet=None,consent=False):
        self.authority.owner(ctx)
        callback=getattr(self,'bitcoin_setup',None)
        require(callable(callback),'SETUP_UNAVAILABLE','Native Bitcoin setup callback unavailable')
        return callback(ctx,wallet=wallet,consent=consent)
