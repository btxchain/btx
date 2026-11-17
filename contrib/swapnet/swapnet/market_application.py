"""Integrated SwapNet market application used by the native embedded Host.

The existing coordinator, native signing bridge and chain drivers remain the
settlement authority. This layer adds discovery, public offers and explicit UX.
"""
from __future__ import annotations
from dataclasses import asdict
import secrets

from .application import Application as BaseApplication, METHODS as BASE_METHODS
from .authorization import Principal
from .assets import Asset
from .canonical import atoms,digest,dumps,loads,exact_fields,hex32,integer
from .errors import require,SwapError
from .marketmaker import Market
from .quote import Quote,SignedQuote
from .market_lifecycle import Participation
from .public_market import PublicMarket,MAX_RECORD
from . import node_invites,market_receipts

MARKET_METHODS={
 'getswapmode':'read','setswapmode':'owner','getswapreadiness':'read','getswapauthinfo':'read',
 'listswappublicoffers':'read','publishswapoffer':'owner','withdrawswapoffer':'owner',
 'requestpublicswapquote':'quote','getswapmakercapacity':'owner',
 'previewswap':'trade','confirmswap':'owner','createswapinvite':'owner',
 'inspectswapinvite':'read','connectswapinvite':'owner',
 'exportswapreceipt':'owner','verifyswapreceipt':'owner',
 'listswaprefusals':'audit','setswapexecutionpolicy':'owner',
 'getswapexecutionpolicy':'owner','setupswapbitcoin':'owner',
 'setswapmarkets':'owner','getsharedp2pinfo':'read'
}
MARKET_COMMANDS=frozenset({'swcap','swoget','swopage','swoffer','sworeq'})
REQUEST_DOMAIN='BTX/SWAPNET/PUBLIC-RFQ/1'

class Application(BaseApplication):
    def __init__(self,*args,startup_mode=None,connect_peer=None,setup_bitcoin=None,
                 shared_core=None,**kwargs):
        super().__init__(*args,**kwargs)
        self.participation=Participation(self.journal,startup_mode)
        self.public=PublicMarket(self.store,self.journal,self.network,self.identity)
        self.connect_peer=connect_peer;self.setup_bitcoin=setup_bitcoin;self.shared_core=shared_core
        self.market_peers=set();self.offer_pages={};self.alternatives={};self.route_attempts={}
        self._incoming_envelope=None;self._next_offer_refresh=0
        with self.store.lock:
            self.store.db.executescript('''
CREATE TABLE IF NOT EXISTS sn_trade_previews(
 id TEXT PRIMARY KEY, principal TEXT NOT NULL, wallet TEXT NOT NULL,
 expires INTEGER NOT NULL, body BLOB NOT NULL, swap_id TEXT);
CREATE TABLE IF NOT EXISTS sn_invite_connections(
 id TEXT PRIMARY KEY, principal TEXT NOT NULL, provider TEXT NOT NULL,
 endpoint TEXT NOT NULL, expires INTEGER NOT NULL, requested INTEGER NOT NULL);
''')

    def rpc(self,ctx,method,params=None):
        require(type(ctx) is Principal,'AUTH','Native authenticated context required')
        require(method in MARKET_METHODS or method in BASE_METHODS,'METHOD_NOT_FOUND','Unknown SwapNet RPC')
        if method not in MARKET_METHODS:return super().rpc(ctx,method,params)
        require(params is None or type(params) is dict,'PARAMS','Expected request object')
        if MARKET_METHODS[method]=='owner':self.authority.owner(ctx)
        try:return getattr(self,'rpc_'+method)(ctx,**(params or {}))
        except TypeError as e:raise SwapError('PARAMS','Unexpected or missing named field') from e

    def rpc_getswapauthinfo(self,ctx):return {'principal':ctx.name,'owner':ctx.owner,'wallet':ctx.wallet}
    def rpc_getswapmode(self,ctx):return self.participation.info()
    def rpc_setswapmode(self,ctx,mode):
        self.authority.owner(ctx)
        result=self.participation.set(mode)
        if not self.participation.may_make():
            self.journal.set_setting('own_advertisement',None)
            # Existing signed quotes/agreements and their reservations are not
            # revoked. Advertisements expire; no new capacity is allocated.
        else:
            self._last_advertisement=0
        return {**result,'pending_authorized_swaps_continue':True}

    def rpc_getswaphealth(self,ctx):
        return {**super().rpc_getswaphealth(ctx),'database_schema':3,'downgrade_requires_explicit_migration':True}

    def rpc_getswapquotes(self,ctx,request_id):
        result=self.service.rpc_getswapquotes(self._context(ctx),request_id)
        decline=self.journal.setting('decline:'+request_id)
        if decline:result={**result,'declined':decline}
        return result

    def rpc_getswapnetworkinfo(self,ctx):
        return {**super().rpc_getswapnetworkinfo(ctx),'participation':self.participation.info(),
                'public_offer_protocol':1,'public_offer_peers':len(self.market_peers),
                'public_offer_catalog_scope':'local signed records; not a complete global order book'}

    def rpc_getswapcapabilities(self,ctx):
        result=super().rpc_getswapcapabilities(ctx)
        result['methods'] += [{'name':k,'scope':v} for k,v in MARKET_METHODS.items()]
        result.update(public_offers=1,invitation_uri=node_invites.PREFIX,
                      firm_offer_assurance='durable local capacity reservation; not collateral or proof of reserves')
        return result

    def rpc_getswapreadiness(self,ctx):
        wallet=self.wallet_info() if self.wallet_info else {}
        assets=super().rpc_listswapassets(ctx)
        ready={a['asset'] for a in assets['assets'] if a['ready']}
        advertised=[]
        for env in self.public.page(self.now(),limit=100)['offers']:
            b=env['body']
            advertised.append({'sell_asset':b['sell_asset'],'buy_asset':b['buy_asset'],
                               'verifiers_ready':b['sell_asset'] in ready and b['buy_asset'] in ready})
        return {'participation':self.participation.info(),'wallet_loaded':wallet.get('wallet_loaded',False),
                'wallet_warning':wallet.get('wallet_warning'),'assets':assets['assets'],
                'advertised_pairs':advertised,'peer_count':len(self.peers),
                'configured_verifiers_required':True,'public_offer_count':len(advertised),
                'automatic_spend_atoms':'0','fiat_supported':False}

    def rpc_listswappublicoffers(self,ctx,after='',limit=32,sell_asset=None,buy_asset=None):
        if sell_asset is not None:Asset.parse(sell_asset)
        if buy_asset is not None:Asset.parse(buy_asset)
        return self.public.page(self.now(),after=after,limit=limit,sell_asset=sell_asset,buy_asset=buy_asset)

    def rpc_publishswapoffer(self,ctx,sell_asset,buy_asset,sizes,kind='indicative',slots=1,ttl=120,offer_id=None):
        self.authority.owner(ctx);self.participation.require_make()
        policies=[p for p in self.markets() if p['principal']==ctx.name and
                  (p['market']['sell_asset'],p['market']['buy_asset'])==(sell_asset,buy_asset)]
        require(len(policies)==1,'MARKET_MISSING','Install one owner-authorized maker policy for this pair first')
        policy=policies[0]
        self.coordinator.check_finality(sell_asset,buy_asset)
        driver=self.coordinator._driver(buy_asset);driver.ready()
        self._maker()  # create the production quote ledger before reserving public capacity
        env=self.public.publish(policy,sizes,kind,slots,ttl,str(driver.inventory()),self.now(),offer_id=offer_id)
        self._publish_offer(env)
        return {'offer':env,'advertised':True,'remote_liquidity_guaranteed':False}

    def rpc_withdrawswapoffer(self,ctx,offer_id):
        self.authority.owner(ctx)
        env=self.public.withdraw(hex32(offer_id),self.now());self._publish_offer(env)
        return {'withdrawal':env,'requester_bound_commitments_preserved':True}

    def rpc_getswapmakercapacity(self,ctx):
        self.authority.owner(ctx);return self.public.local_capacity(self.now())

    def _publish_offer(self,env,exclude=None):
        raw=dumps(env).decode()
        for peer in sorted(self.market_peers):
            if peer!=exclude:self.send(peer,'swoffer',raw)
        if self.shared_core:
            b=env['body']
            self.shared_core('record',{'service':'swapnet','key':b['provider']+'|'+b['offer_id'],
                                      'sequence':b['sequence'],'expires_at':b['expires_at'],'record':raw})

    def peer_connected(self,peer):
        integer(peer,lo=0,hi=(1<<53)-1)
        if peer in self.peers:return
        require(len(self.peers)<128,'PEER_LIMIT','Peer limit reached');self.peers.add(peer)
        if self.participation.mode!='recovery':
            self.send(peer,'swget',dumps({'after':'','limit':32}).decode())
            self.send(peer,'swcap',dumps({'version':1,'network':self.network,'public_offers':1}).decode())
        if self.participation.may_make():
            ad=self.journal.setting('own_advertisement')
            if ad and ad['body']['expires_at']>self.now():self.send(peer,'swprov',dumps(ad).decode())

    def peer_disconnected(self,peer):
        super().peer_disconnected(peer);self.market_peers.discard(peer);self.offer_pages.pop(peer,None)
        for identity in list(self.alternatives):
            self.alternatives[identity].pop(peer,None)
            if not self.alternatives[identity]:del self.alternatives[identity]

    def _learn_route(self,identity,peer,expires):
        super()._learn_route(identity,peer,expires)
        if self.shared_core:
            try:self.shared_core('learn',{'identity':identity,'peer':str(peer),'expires_at':expires})
            except SwapError:pass  # existing obligations retain bounded native-peer fallback
        if identity not in self.alternatives and len(self.alternatives)>=8192:
            oldest=next(iter(self.alternatives));del self.alternatives[oldest]
        candidates=self.alternatives.setdefault(identity,{})
        if peer in candidates or len(candidates)<4:candidates[peer]=expires

    def _route(self,recipient,command,packet,hops=4,exclude=None):
        raw=dumps({'packet':packet,'hops':hops}).decode()
        key=digest('BTX/SWAPNET/ROUTE-ATTEMPT/1',packet)
        attempt=self.route_attempts.get(key,0);self.route_attempts[key]=attempt+1
        if len(self.route_attempts)>4096:self.route_attempts.pop(next(iter(self.route_attempts)))
        candidates=[p for p,e in self.alternatives.get(recipient,{}).items()
                    if e>self.now() and p in self.peers and p!=exclude]
        if self.shared_core and recipient!='*':
            try:
                shared=self.shared_core('routes',{'identity':recipient}).get('routes',[])
                candidates=[int(p) for p in shared if str(p).isdigit() and int(p) in self.peers and int(p)!=exclude]
            except (SwapError,ValueError,TypeError):pass
        if recipient!='*' and candidates and attempt<len(candidates):
            if self.send(candidates[attempt%len(candidates)],command,raw):return True
        # No ACK means queued delivery was not proven. Later retries try another
        # route, then a bounded alternate search. No route is a custody authority.
        targets=[p for p in sorted(self.market_peers if command in MARKET_COMMANDS else self.peers) if p!=exclude]
        if targets:
            start=attempt%len(targets);targets=(targets[start:]+targets[:start])[:8]
        sent=False
        for p in targets:sent=bool(self.send(p,command,raw)) or sent
        return sent

    def _start_offer_page(self,peer,after='',pages=0):
        if pages>=256:return
        token=secrets.token_hex(16)
        self.offer_pages[peer]={'token':token,'pages':pages,'after':after,'expires':self.now()+30}
        self.send(peer,'swoget',dumps({'version':1,'token':token,'after':after,'limit':8}).decode())

    def on_message(self,peer,command,raw):
        require(peer in self.peers,'PEER_NOT_ADMITTED','Peer handshake is incomplete')
        if command=='swcap':
            p=loads(raw);exact_fields(p,{'version','network','public_offers'})
            require(p['version']==1 and p['network']==self.network and p['public_offers']==1,
                    'CAPABILITY','Unsupported public market capability')
            first=peer not in self.market_peers;self.market_peers.add(peer)
            if first and self.participation.mode!='recovery':
                self.send(peer,'swcap',dumps({'version':1,'network':self.network,'public_offers':1}).decode())
                self._start_offer_page(peer)
            return
        if command in {'swoget','swopage','swoffer','sworeq'}:
            require(peer in self.market_peers,'CAPABILITY','Public market capability not negotiated')
        if command=='swoget':
            p=loads(raw);exact_fields(p,{'version','token','after','limit'})
            require(p['version']==1 and type(p['token']) is str and len(p['token'])==32,'PAGE','Invalid page request')
            integer(p['limit'],lo=1,hi=8)
            page=self.public.page(self.now(),after=p['after'],limit=p['limit'],include_withdrawn=True)
            offers=page['offers'];next_cursor=page['next_cursor']
            while offers:
                result={'version':1,'token':p['token'],'offers':offers,'next_cursor':next_cursor}
                try:encoded=dumps(result)
                except SwapError:encoded=b'x'*65536
                if len(encoded)<=60000:break
                offers=offers[:-1]
                if offers:
                    b=offers[-1]['body'];next_cursor=b['provider']+'|'+b['offer_id']
            self.send(peer,'swopage',dumps({'version':1,'token':p['token'],'offers':offers,'next_cursor':next_cursor if offers else None}).decode())
            return
        if command=='swopage':
            p=loads(raw);exact_fields(p,{'version','token','offers','next_cursor'})
            pending=self.offer_pages.get(peer)
            require(pending and pending['token']==p['token'] and self.now()<=pending['expires'],'PAGE','Unsolicited or stale page')
            require(type(p['offers']) is list and len(p['offers'])<=8,'PAGE','Too many page records')
            last=pending['after']
            for env in p['offers']:
                b=env['body'];key=b['provider']+'|'+b['offer_id']
                require(key>last,'PAGE','Page is not strictly ordered');last=key
                self.public.ingest(env,self.now());self._learn_route(b['provider'],peer,b['expires_at'])
            cursor=p['next_cursor']
            require(cursor is None or (p['offers'] and cursor==last),'PAGE','Invalid continuation cursor')
            if cursor:self._start_offer_page(peer,cursor,pending['pages']+1)
            else:self.offer_pages.pop(peer,None)
            return
        if command=='swoffer':
            env=loads(raw)
            added=self.public.ingest(env,self.now());b=env['body']
            self._learn_route(b['provider'],peer,b['expires_at'])
            if added:self._publish_offer(env,exclude=peer)
            return
        if command=='sworeq':
            wrapper=loads(raw);exact_fields(wrapper,{'packet','hops'});integer(wrapper['hops'],lo=0,hi=4)
            p=wrapper['packet'];exact_fields(p,{'body','signature'});b=p['body']
            exact_fields(b,{'version','network','sender','recipient','sequence','issued_at','expires_at','request_id','payload'})
            require(b['version']==1 and b['network']==self.network,'NETWORK','Wrong public RFQ network')
            integer(b['sequence'],lo=1);integer(b['issued_at']);integer(b['expires_at']);hex32(b['request_id'])
            require(b['issued_at']<=self.now()<b['expires_at']<=b['issued_at']+120,'QUOTE_EXPIRED','Public RFQ expired')
            require(type(b['sender']) is str and 0<len(b['sender'])<=256 and type(b['recipient']) is str and 0<len(b['recipient'])<=256,'IDENTITY','Invalid identity')
            require(type(p['signature']) is str and 0<len(p['signature'])<=16384,'SIGNATURE','Invalid signature')
            require(self.identity.verify(b['sender'],p['signature'],REQUEST_DOMAIN+':'+digest(REQUEST_DOMAIN,b)) is True,'BAD_SIGNATURE','Public RFQ signature rejected')
            self._learn_route(b['sender'],peer,b['expires_at'])
            mid=digest(REQUEST_DOMAIN+'/PACKET',p)
            if b['recipient']!=self._identity():
                if wrapper['hops'] and self._remember(mid,b['expires_at']):self._route(b['recipient'],command,p,wrapper['hops']-1,peer)
                return
            self._receive_public_request(b)
            return
        self._incoming_envelope=None
        if command in {'swquote','swterms'}:
            try:self._incoming_envelope=loads(raw)['packet']
            except (KeyError,TypeError,SwapError):pass
        try:return super().on_message(peer,command,raw)
        finally:self._incoming_envelope=None

    def _receive_public_request(self,body):
        p=body['payload'];exact_fields(p,{'offer_id','sequence','tier','rfq'})
        rfq=p['rfq'];rid=body['request_id'];sender=body['sender']
        exact_fields(rfq,{'network','requester','sell_asset','buy_asset','sell_atoms','nonce','issued_at','expires_at'})
        require(digest('BTX/SWAPNET/RFQ/1',rfq)==rid,'RFQ_BINDING','Wrong request identifier')
        require(rfq['requester']==digest('BTX/SWAPNET/REQUESTER/2',{'identity':sender,'nonce':rfq['nonce']}),'RFQ_BINDING','Wrong requester')
        try:
            self.participation.require_make()
            env,slot=self.public.allocate(hex32(p['offer_id']),p['sequence'],p['tier'],rfq,sender,self.now())
            if slot:policy=self.public.policy_for_slot(slot)
            else:
                policies=[x for x in self.markets() if (x['market']['sell_asset'],x['market']['buy_asset'])==(rfq['sell_asset'],rfq['buy_asset'])]
                require(policies,'MARKET_MISSING','Maker no longer quotes this pair');policy=policies[0]
            self.coordinator.check_finality(rfq['sell_asset'],rfq['buy_asset'])
            driver=self.coordinator._driver(rfq['buy_asset']);driver.ready()
            maker=self._maker();maker.set_verified_inventory(rfq['buy_asset'],str(driver.inventory()),self.now())
            market=dict(policy['market']);market['expires_at']=min(market['expires_at'],env['body']['expires_at'])
            signed=maker.quote(rfq,Market(**market),self.now(),public_slot=slot)
            if slot:self.public.bind_quote(slot,signed.quote,self.now())
            self._quote_within_mandate(policy,signed.quote,sender)
            self.emit(sender,'quote',rid,{'request_id':rid,'quote':signed.as_dict()})
        except SwapError as e:
            self.emit(sender,'decline',rid,{'request_id':rid,'code':e.code,'message':e.message})

    def _process(self,b):
        kind=b['kind'];p=b['payload'];rid=b['swap_id']
        if kind=='rfq' and not self.participation.may_make():return
        if kind=='proposal':
            with self.store.lock:existing=self.store.db.execute('SELECT 1 FROM sn_negotiations WHERE id=?',(rid,)).fetchone()
            if not existing and not self.participation.may_make():
                self.emit(b['sender'],'decline',rid,{'request_id':digest('BTX/SWAPNET/RFQ/1',p['rfq']),'code':'MODE_DISABLED','message':'Maker is not accepting new commitments'})
                return
            q=Quote.parse(p['quote']['quote'])
            policy=self.public.policy_for_quote(q.id)
            if policy:
                try:return self.coordinator.receive_proposal(b['sender'],rid,p,policy)
                except SwapError as e:
                    self.emit(b['sender'],'decline',rid,{'request_id':digest('BTX/SWAPNET/RFQ/1',p['rfq']),'code':e.code,'message':e.message});return
        if kind in {'quote','decline'}:
            request_id=p.get('request_id')
            with self.store.lock:
                target=self.store.db.execute('SELECT provider,body FROM sn_public_requests WHERE request_id=?',(request_id,)).fetchone()
                known=self.store.db.execute('SELECT 1 FROM rfqs WHERE id=?',(request_id,)).fetchone()
            require(known,'RFQ_MISSING','No local request for quote or refusal')
            if target:
                require(target[0]==b['sender'],'QUOTE_BINDING','Reply came from a different provider')
                if kind=='quote':
                    request=loads(target[1]);offer=request['offer'];tier=offer['body']['tiers'][request['tier']]
                    q=Quote.parse(p['quote']['quote'])
                    if offer['body']['kind']=='firm':
                        require((q.buy_atoms,q.maker_fee_atoms,q.max_receive_network_fee_atoms)==(tier['buy_atoms'],tier['maker_fee_atoms'],tier['max_receive_network_fee_atoms']),
                                'OFFER_BINDING','Firm quote changed published consideration')
            result=super()._process(b)
            with self.store.transaction() as db:
                if target:db.execute('UPDATE sn_public_requests SET completed=1 WHERE request_id=?',(request_id,))
                if kind=='decline' and self._incoming_envelope:
                    db.execute('INSERT OR REPLACE INTO sn_market_refusals VALUES(?,?,?,?)',(request_id,b['sender'],dumps(self._incoming_envelope),self.now()))
                    db.execute('DELETE FROM sn_market_refusals WHERE rowid NOT IN (SELECT rowid FROM sn_market_refusals ORDER BY observed DESC LIMIT 1024)')
            return result
        return super()._process(b)

    def rpc_requestpublicswapquote(self,ctx,provider,offer_id,tier=0):
        env=self.public.get(provider,hex32(offer_id),self.now());b=env['body']
        integer(tier,lo=0,hi=len(b['tiers'])-1);t=b['tiers'][tier]
        nonce=secrets.token_hex(32);identity=self.identity.address();now=self.now()
        rfq={'network':self.network,'requester':digest('BTX/SWAPNET/REQUESTER/2',{'identity':identity,'nonce':nonce}),
             'sell_asset':b['sell_asset'],'buy_asset':b['buy_asset'],'sell_atoms':t['sell_atoms'],
             'nonce':nonce,'issued_at':now,'expires_at':min(now+120,b['expires_at'])}
        rid=digest('BTX/SWAPNET/RFQ/1',rfq)
        with self.store.transaction() as db:
            db.execute('DELETE FROM rfqs WHERE expires<=?',(now,))
            require(db.execute('SELECT count(*) FROM rfqs').fetchone()[0]<256,'RFQ_LIMIT','Too many requests')
            db.execute('INSERT INTO rfqs VALUES(?,?,?,?)',(rid,rfq['expires_at'],ctx.name,dumps(rfq)))
            db.execute('INSERT INTO sn_public_requests VALUES(?,?,?,?,?,?,0,0)',
                       (rid,ctx.name,provider,dumps({'rfq':rfq,'offer':env,'tier':tier}),rfq['expires_at'],now))
        self._send_public_requests()
        return {'request_id':rid,'provider':provider,'expires_at':rfq['expires_at'],
                'spending_authority':False,'privacy':'addressed request; relays may observe its contents'}

    def _send_public_requests(self):
        now=self.now()
        with self.store.lock:
            rows=self.store.db.execute('SELECT request_id,provider,body,attempts FROM sn_public_requests WHERE completed=0 AND expires>? AND next_try<=? ORDER BY next_try LIMIT 8',(now,now)).fetchall()
        for rid,provider,raw,attempt in rows:
            request=loads(raw);offer=request['offer']['body'];rfq=request['rfq']
            body={'version':1,'network':self.network,'sender':self.identity.address(),'recipient':provider,
                  'sequence':self.journal.next_sequence('public-rfq:'+self.identity.address()),
                  'issued_at':now,'expires_at':rfq['expires_at'],'request_id':rid,
                  'payload':{'offer_id':offer['offer_id'],'sequence':offer['sequence'],'tier':request['tier'],'rfq':rfq}}
            packet={'body':body,'signature':self.identity.sign(REQUEST_DOMAIN+':'+digest(REQUEST_DOMAIN,body))}
            # Directed routes are tried before bounded relay. The original RFQ
            # id remains stable so retries cannot allocate additional capacity.
            candidates=[p for p,e in self.alternatives.get(provider,{}).items() if e>now and p in self.market_peers]
            if candidates and attempt<len(candidates):
                self.send(candidates[attempt%len(candidates)],'sworeq',dumps({'packet':packet,'hops':4}).decode())
            else:
                sent=0
                for peer in sorted(self.market_peers):
                    self.send(peer,'sworeq',dumps({'packet':packet,'hops':4}).decode());sent+=1
                    if sent==8:break
            with self.store.transaction() as db:
                db.execute('UPDATE sn_public_requests SET attempts=attempts+1,next_try=? WHERE request_id=?',(now+min(20,3*(attempt+1)),rid))

    def advertise(self):
        if not self.participation.may_make():return {'advertised':False,'reason':'maker_mode_disabled'}
        return super().advertise()

    def tick(self):
        # Preserve the maintained coordinator, its per-swap backoff, complete
        # history reader and deep-reorg recovery. No new-offer preflight runs here.
        super().tick()
        self.public.close_expired(self.now())
        if self.participation.mode!='recovery':
            self._send_public_requests()
            if self.now()>=self._next_offer_refresh:
                for peer in sorted(self.market_peers):
                    if peer not in self.offer_pages:self._start_offer_page(peer)
                self._next_offer_refresh=self.now()+60
        for peer,pending in list(self.offer_pages.items()):
            if pending['expires']<self.now():self.offer_pages.pop(peer,None)

    def rpc_acceptswapquote(self,ctx,quote_id,mandate_id,max_local_fee_atoms,refund_fee_atoms=None,claim_fee_atoms=None):
        self.participation.require_trade()
        self._check_execution_policy(ctx,quote_id)
        return super().rpc_acceptswapquote(ctx,quote_id,mandate_id,max_local_fee_atoms,refund_fee_atoms,claim_fee_atoms)

    def rpc_setswapmarket(self,ctx,market,mandate_id,max_local_fee_atoms,refund_fee_atoms,claim_fee_atoms,enabled=True):
        self.participation.require_make()
        return super().rpc_setswapmarket(ctx,market,mandate_id,max_local_fee_atoms,refund_fee_atoms,claim_fee_atoms,enabled)

    def rpc_setswapmarkets(self,ctx,markets):
        self.authority.owner(ctx);self.participation.require_make()
        require(type(markets) is list and 1<=len(markets)<=2,'MARKETS','One or two market configurations required')
        # Validate and authorize every policy before persisting either one.
        old=self.markets();updates=[]
        for entry in markets:
            exact_fields(entry,{'market','mandate_id','max_local_fee_atoms','refund_fee_atoms','claim_fee_atoms'})
            m=Market(**entry['market']);mid=hex32(entry['mandate_id'])
            self.coordinator._driver(m.sell_asset).ready();self.coordinator._driver(m.buy_asset).ready()
            with self.store.lock:r=self.store.db.execute('SELECT body,revoked FROM mandates WHERE id=?',(mid,)).fetchone()
            require(r and not r[1] and loads(r[0])['principal']==ctx.name and loads(r[0])['asset']==m.buy_asset,'MANDATE_SCOPE','Maker mandate scope mismatch')
            for fee in ('max_local_fee_atoms','refund_fee_atoms','claim_fee_atoms'):atoms(entry[fee],positive=True)
            require(atoms(entry['refund_fee_atoms'])<=atoms(entry['max_local_fee_atoms']),'FEE_CAP','Refund exceeds cap')
            updates.append({**entry,'market':asdict(m),'principal':ctx.name,'wallet':ctx.wallet})
        pairs=[(x['market']['sell_asset'],x['market']['buy_asset']) for x in updates]
        require(len(set(pairs))==len(pairs),'MARKETS','Duplicate pair')
        combined=[x for x in old if (x['market']['sell_asset'],x['market']['buy_asset']) not in pairs]+updates
        require(len(combined)<=16,'MARKET_LIMIT','Too many markets')
        self.journal.set_setting('markets',combined);self.advertise()
        return {'installed':len(updates),'atomic_policy_update':True,'automatic_spend_atoms':'0'}

    def _quote_for(self,ctx,quote_id):
        with self.store.lock:
            row=self.store.db.execute('SELECT body FROM quotes WHERE id=?',(hex32(quote_id),)).fetchone()
            requests=self.store.db.execute('SELECT body FROM rfqs WHERE principal=?',(ctx.name,)).fetchall()
        require(row,'QUOTE_MISSING','Quote unavailable');env=loads(row[0]);q=Quote.parse(env['quote'])
        require(any(loads(r[0])['requester']==q.requester for r in requests),'FORBIDDEN','Quote belongs to another principal')
        SignedQuote(q,env['signature']).verify(self.identity.verify,self.network,q.requester,self.now())
        return env,q

    def rpc_previewswap(self,ctx,quote_id,max_local_fee_atoms,refund_fee_atoms=None,claim_fee_atoms=None,min_receive_atoms=None):
        env,q=self._quote_for(ctx,quote_id);self._check_execution_policy(ctx,quote_id)
        outgoing=atoms(max_local_fee_atoms,positive=True)
        refund=atoms(refund_fee_atoms if refund_fee_atoms is not None else str(outgoing//2),positive=True)
        claim=atoms(claim_fee_atoms if claim_fee_atoms is not None else q.max_receive_network_fee_atoms)
        require(refund<=outgoing and claim<=atoms(q.max_receive_network_fee_atoms),'FEE_CAP','Preview fee exceeds quote or local cap')
        minimum=atoms(min_receive_atoms if min_receive_atoms is not None else str(q.net_buy),positive=True)
        require(q.net_buy>=minimum,'PRICE_PROTECTION','Quote does not meet minimum consideration')
        now=self.now();token=secrets.token_hex(32)
        mandate={'principal':ctx.name,'asset':q.sell_asset,'max_total_atoms':str(atoms(q.sell_atoms)+outgoing),
                 'max_trade_atoms':q.sell_atoms,'max_fee_atoms':str(outgoing),
                 'expires_at':min(q.expires_at,now+60),'nonce':secrets.token_hex(32)}
        body={'quote':env,'max_local_fee_atoms':str(outgoing),'refund_fee_atoms':str(refund),
              'claim_fee_atoms':str(claim),'minimum_receive_atoms':str(minimum),'mandate':mandate,
              'sell_asset':q.sell_asset,'buy_asset':q.buy_asset,'sell_atoms':q.sell_atoms,
              'maximum_send_atoms':str(atoms(q.sell_atoms)+outgoing),'net_receive_floor_atoms':str(q.net_buy),
              'provider':q.provider,'expires_at':min(q.expires_at,now+30)}
        with self.store.transaction() as db:
            db.execute('DELETE FROM sn_trade_previews WHERE expires<? AND swap_id IS NULL',(now-300,))
            require(db.execute('SELECT count(*) FROM sn_trade_previews WHERE swap_id IS NULL').fetchone()[0]<256,'PREVIEW_LIMIT','Too many previews')
            db.execute('INSERT INTO sn_trade_previews VALUES(?,?,?,?,?,NULL)',(token,ctx.name,ctx.wallet,body['expires_at'],dumps(body)))
        return {'preview_id':token,**{k:v for k,v in body.items() if k not in {'quote','mandate'}},
                'requires_owner_confirmation':True,'funds_reserved':False,'refundable_after_chain_deadline':True}

    def rpc_confirmswap(self,ctx,preview_id):
        self.authority.owner(ctx)
        with self.store.lock:row=self.store.db.execute('SELECT principal,wallet,expires,body,swap_id FROM sn_trade_previews WHERE id=?',(hex32(preview_id),)).fetchone()
        require(row and row[0]==ctx.name and row[1]==ctx.wallet,'FORBIDDEN','Preview does not belong to this principal and wallet')
        body=loads(row[3]);q=Quote.parse(body['quote']['quote'])
        sid=digest('BTX/SWAPNET/SWAP/2',{'quote_id':q.id,'initiator':self.identity.address()})
        # Recover the exact already-started trade after a reply/write failure;
        # do not make a new mandate or require the old quote to remain live.
        with self.store.lock:existing=self.store.db.execute('SELECT principal FROM sn_negotiations WHERE id=?',(sid,)).fetchone()
        if existing:
            require(existing[0]==ctx.name,'FORBIDDEN','Trade belongs to another principal')
            result=self.coordinator.get(ctx,sid)
        else:
            self.participation.require_trade()
            require(self.now()<row[2],'PREVIEW_EXPIRED','Review a fresh quote')
            self._quote_for(ctx,q.id)
            from .policy import Mandate
            mandate=Mandate(**body['mandate']);mid=mandate.id
            with self.store.lock:installed=self.store.db.execute('SELECT body FROM mandates WHERE id=?',(mid,)).fetchone()
            if not installed:self.authority.install(ctx,body['mandate'])
            else:require(loads(installed[0])==body['mandate'],'MANDATE_SCOPE','Stored one-shot mandate differs')
            result=self.rpc_acceptswapquote(ctx,q.id,mid,body['max_local_fee_atoms'],body['refund_fee_atoms'],body['claim_fee_atoms'])
        with self.store.transaction() as db:db.execute('UPDATE sn_trade_previews SET swap_id=? WHERE id=?',(sid,preview_id))
        return result

    def rpc_createswapinvite(self,ctx,endpoints,ttl=86400,allow_private=False):
        self.authority.owner(ctx);require(type(allow_private) is bool,'PARAMS','Invalid private-network consent')
        return node_invites.create(self.identity,self.network,endpoints,self.now(),ttl,allow_private)

    def rpc_inspectswapinvite(self,ctx,uri,allow_private=False):
        require(type(allow_private) is bool,'PARAMS','Invalid private-network consent')
        return node_invites.inspect(uri,self.network,self.now(),self.identity.verify,allow_private)

    def rpc_connectswapinvite(self,ctx,uri,endpoint_index=0,allow_private=False,allow_dns=False):
        self.authority.owner(ctx)
        require(type(allow_private) is bool and type(allow_dns) is bool,'PARAMS','Explicit network consent must be boolean')
        info=node_invites.inspect(uri,self.network,self.now(),self.identity.verify,allow_private)
        integer(endpoint_index,lo=0,hi=len(info['endpoints'])-1);selected=info['endpoints'][endpoint_index]
        require(selected['kind']!='dns' or allow_dns,'INVITE_DNS','DNS endpoint requires explicit name-resolution consent')
        require(self.connect_peer is not None,'NATIVE_UNAVAILABLE','Native P2P connection adapter unavailable')
        # This callback only permits addnode(onetry), never arbitrary RPC or
        # external-chain verifier configuration. A URI is not a wallet mandate.
        outcome=self.connect_peer(selected['endpoint'])
        with self.store.transaction() as db:
            db.execute('INSERT OR REPLACE INTO sn_invite_connections VALUES(?,?,?,?,?,?)',
                       (info['invitation_id'],ctx.name,info['provider'],selected['endpoint'],info['expires_at'],self.now()))
        return {'invitation_id':info['invitation_id'],'provider':info['provider'],
                'endpoint':selected['endpoint'],'connection_requested':True,'connected':False,
                'identity_verified_on_transport':False,'spending_authority':False,'native_result':outcome}

    def rpc_exportswapreceipt(self,ctx,swap_id):
        self.authority.owner(ctx);return market_receipts.export_receipt(self,ctx,swap_id)
    def rpc_verifyswapreceipt(self,ctx,receipt):
        self.authority.owner(ctx);return market_receipts.verify_receipt(self,receipt)

    def rpc_listswaprefusals(self,ctx,request_id):
        with self.store.lock:
            owner=self.store.db.execute('SELECT principal FROM rfqs WHERE id=?',(hex32(request_id),)).fetchone()
            require(owner and owner[0]==ctx.name,'FORBIDDEN','Request belongs to another principal')
            rows=self.store.db.execute('SELECT provider,envelope,observed FROM sn_market_refusals WHERE request_id=?',(request_id,)).fetchall()
        return {'refusals':[{'provider':p,'signed_envelope':loads(e),'observed_at':t} for p,e,t in rows],
                'no_reply_is_proof_of_refusal':False}

    def rpc_setswapexecutionpolicy(self,ctx,policy):
        self.authority.owner(ctx);exact_fields(policy,{'minimum_receive_atoms','reference','max_deviation_bps'})
        atoms(policy['minimum_receive_atoms']);integer(policy['max_deviation_bps'],lo=0,hi=10000)
        reference=policy['reference']
        if reference is not None:
            exact_fields(reference,{'sell_asset','buy_asset','sell_atoms','net_buy_atoms','expires_at','provenance'})
            Asset.parse(reference['sell_asset']);Asset.parse(reference['buy_asset'])
            atoms(reference['sell_atoms'],positive=True);atoms(reference['net_buy_atoms'],positive=True)
            integer(reference['expires_at']);require(self.now()<reference['expires_at']<=self.now()+300,'REFERENCE_STALE','Reference lifetime exceeds five minutes')
            require(type(reference['provenance']) is str and 0<len(reference['provenance'])<=256,'REFERENCE','Reference needs an owner-supplied provenance label')
        self.journal.set_setting('market.execution:'+ctx.name,policy)
        return {'saved':True,'official_price':False,'reference_is_owner_selected':True}
    def rpc_getswapexecutionpolicy(self,ctx):
        self.authority.owner(ctx);return self.journal.setting('market.execution:'+ctx.name,{'minimum_receive_atoms':'0','reference':None,'max_deviation_bps':10000})
    def _check_execution_policy(self,ctx,quote_id):
        _,q=self._quote_for(ctx,quote_id)
        p=self.journal.setting('market.execution:'+ctx.name,None)
        if not p:return
        require(q.net_buy>=atoms(p['minimum_receive_atoms']),'PRICE_PROTECTION','Quote below owner minimum')
        r=p['reference']
        if r:
            require(self.now()<r['expires_at'],'REFERENCE_STALE','Owner reference expired')
            require((q.sell_asset,q.buy_asset,q.sell_atoms)==(r['sell_asset'],r['buy_asset'],r['sell_atoms']),'REFERENCE_SCOPE','Reference does not cover this exact size and pair')
            require(q.net_buy*10000>=atoms(r['net_buy_atoms'])*(10000-p['max_deviation_bps']),
                    'PRICE_PROTECTION','Quote outside owner-selected tolerance')

    def rpc_setupswapbitcoin(self,ctx,policy):
        self.authority.owner(ctx)
        require(self.setup_bitcoin is not None,'NATIVE_UNAVAILABLE','Bitcoin setup adapter unavailable')
        result=self.setup_bitcoin(policy)
        return self.rpc_setswapassetpolicy(ctx,result)

    def rpc_getsharedp2pinfo(self,ctx):
        if self.shared_core:return self.shared_core('status',{})
        return {'available':False,'reason':'native shared control-plane adapter unavailable',
                'wallet_authority':False}
