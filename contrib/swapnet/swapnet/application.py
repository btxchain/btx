"""Native-node application: signed discovery, bounded routing, RFQ, and execution.

The transport owns peer admission and byte limits. This layer verifies identities
before changing routing or durable state. Message bodies never become Principal
objects, never choose RPC URLs, and never pass arbitrary methods to wallets.
"""
from dataclasses import asdict
from collections import OrderedDict
import secrets
import time
from .canonical import loads,dumps,digest,hex32,exact_fields,integer,atoms
from .authorization import Principal,Authority
from .coordinator import Coordinator
from .journal import Journal
from .service import Service,Context,METHODS as LEGACY_METHODS
from .marketmaker import Maker,Market
from .quote import Quote
from .policy import SafetyPolicy
from .errors import require,SwapError

VERSION='2.0.0'
NEW_METHODS={
 'setswapmarket':'owner','listswapmarkets':'read','getswapwalletinfo':'read',
 'setswapassetpolicy':'owner','listswapassetpolicies':'read','getswaprouteinfo':'read',
 'exportswaprecovery':'owner','bumpswapfee':'trade','getswapevents':'audit',
 'getswapvalidationinfo':'read'
}
METHODS={**LEGACY_METHODS,**NEW_METHODS}
PACKET_COMMANDS={'rfq':'swrfq','quote':'swquote','proposal':'swterms','agreement':'swterms','commit':'swterms',
                 'funded':'swreceipt','cancel':'swterms','ack':'swreceipt'}

class NativeIdentity:
    def __init__(self,network,journal,rpc,wallet):self.network,self.journal,self.rpc,self.wallet=network,journal,rpc,wallet
    def peek(self):return self.journal.setting('identity')
    def address(self):
        address=self.peek()
        if not address:
            address=self.wallet('getnewaddress','swapnet-provider-identity','p2mr')
            self.journal.set_setting('identity',address)
        return address
    def sign(self,message):return self.wallet('signmessage',self.address(),message)
    def verify(self,address,signature,message):
        try:return self.rpc('verifymessage',address,signature,message) is True
        except SwapError:return False

class Application:
    def __init__(self,store,network,identity,vault,drivers,send,*,clock=None,policy=None,configure_asset=None,
                 wallet_info=None,export_recovery=None):
        self.store,self.network,self.identity,self.vault,self.drivers,self.send=store,hex32(network),identity,vault,drivers,send
        self.now=clock or (lambda:int(time.time()));self.journal=Journal(store);self.authority=Authority(store,self.journal,self.now)
        self.routes={};self.peers=set();self.relay_seen=OrderedDict();self.packet_errors=0
        self.recent_packet_errors=[];self.last_tick_error=None
        self.configure_asset,self.wallet_info,self.export_recovery=configure_asset,wallet_info,export_recovery
        self.service=Service(store,network,identity.verify,clock=self.now,enqueue=lambda *args:None)
        self.coordinator=Coordinator(self.journal,self.authority,drivers,identity,vault,self.emit,clock=self.now,policy=policy)
        self.maker=None;self._last_advertisement=0;self._last_maintenance=0
    def note_packet_error(self,code,message):
        self.packet_errors+=1
        self.recent_packet_errors.append({'code':str(code),'message':str(message)[:160]})
        del self.recent_packet_errors[:-8]
    def _identity(self):return self.identity.peek() if hasattr(self.identity,'peek') else self.identity.address()
    def _maker(self):
        if self.maker is None:
            self.maker=Maker(self.store,self.network,self.identity.address(),lambda addr,msg:self.identity.sign(msg),self.identity.verify)
        return self.maker
    def markets(self):return self.journal.setting('markets',[])
    def _learn_route(self,identity,peer,expires):
        if identity not in self.routes and len(self.routes)>=8192:
            oldest=min(self.routes,key=lambda k:self.routes[k][1]);self.routes.pop(oldest)
        self.routes[identity]=(peer,expires)
    def _remember(self,key,expires):
        now=self.now()
        for k,v in list(self.relay_seen.items()):
            if v<=now:del self.relay_seen[k]
        if key in self.relay_seen:return False
        if len(self.relay_seen)>=4096:self.relay_seen.popitem(last=False)
        self.relay_seen[key]=expires;return True
    def peer_connected(self,peer):
        integer(peer,lo=0,hi=(1<<53)-1)
        if peer in self.peers:return
        require(len(self.peers)<128,'PEER_LIMIT','Peer limit reached');self.peers.add(peer)
        self.send(peer,'swget',dumps({'after':'','limit':32}).decode())
        ad=self.journal.setting('own_advertisement')
        if ad and ad['body']['expires_at']>self.now():self.send(peer,'swprov',dumps(ad).decode())
    def peer_disconnected(self,peer):
        self.peers.discard(peer);self.routes={k:v for k,v in self.routes.items() if v[0]!=peer}
    def emit(self,recipient,kind,sid,payload):
        require(kind in PACKET_COMMANDS,'MESSAGE_KIND','Unknown packet kind');hex32(sid)
        now=self.now();sender=self.identity.address()
        body={'version':2,'network':self.network,'sender':sender,'recipient':recipient,'kind':kind,'swap_id':sid,
              'sequence':self.journal.next_sequence(sender),'issued_at':now,'expires_at':now+600,'payload':payload}
        signature=self.identity.sign('BTX/SWAPNET/ENVELOPE/2:'+digest('BTX/SWAPNET/ENVELOPE/2',body))
        packet={'body':body,'signature':signature}
        return self.journal.enqueue(recipient,PACKET_COMMANDS[kind],packet,now)
    def _validate_packet(self,packet,command):
        exact_fields(packet,{'body','signature'});b=packet['body']
        exact_fields(b,{'version','network','sender','recipient','kind','swap_id','sequence','issued_at','expires_at','payload'})
        require(b['version']==2 and type(b['version']) is int and b['network']==self.network,'NETWORK','Wrong protocol/network')
        require(PACKET_COMMANDS.get(b['kind'])==command,'MESSAGE_KIND','Command/body mismatch')
        hex32(b['swap_id']);integer(b['sequence'],lo=1);integer(b['issued_at']);integer(b['expires_at'])
        require(b['issued_at']<=self.now()<b['expires_at']<=b['issued_at']+600,'MESSAGE_EXPIRED','Expired or future packet')
        require(type(b['sender']) is str and 0<len(b['sender'])<=256 and type(b['recipient']) is str and 0<len(b['recipient'])<=256,
                'IDENTITY','Malformed routing identity')
        require(type(packet['signature']) is str and 0<len(packet['signature'])<=16384,'SIGNATURE','Invalid signature length')
        message='BTX/SWAPNET/ENVELOPE/2:'+digest('BTX/SWAPNET/ENVELOPE/2',b)
        require(self.identity.verify(b['sender'],packet['signature'],message) is True,'BAD_SIGNATURE','Packet signature rejected')
        return b
    def _route(self,recipient,command,packet,hops=4,exclude=None):
        raw=dumps({'packet':packet,'hops':hops}).decode();route=self.routes.get(recipient)
        if recipient!='*' and route and route[1]>self.now() and route[0] in self.peers and route[0]!=exclude:
            return bool(self.send(route[0],command,raw))
        # Bounded route search. Endpoints authenticate messages; intermediary nodes
        # cannot authorize funds or alter payloads. No secret travels in this path.
        targets=[p for p in sorted(self.peers) if p!=exclude][:8]
        return any([bool(self.send(p,command,raw)) for p in targets])
    def on_message(self,peer,command,raw):
        require(peer in self.peers,'PEER_NOT_ADMITTED','Peer handshake is incomplete')
        if command=='swget':
            q=loads(raw);exact_fields(q,{'after','limit'});integer(q['limit'],lo=1,hi=32)
            result=self.service.catalog.search(self.now(),after=q['after'],limit=q['limit'])
            for env in result['providers']:self.send(peer,'swprov',dumps(env).decode())
            return
        if command=='swprov':
            env=loads(raw);provider_id=env.get('body',{}).get('identity')
            try:self.service.catalog.ingest(env,self.now())
            except SwapError as e:
                if e.code!='REPLAY':raise
                # A duplicate must be byte-for-byte the still-live signed record.
                with self.store.lock:r=self.store.db.execute('SELECT body FROM providers WHERE identity=? AND expires>?',(provider_id,self.now())).fetchone()
                require(r and bytes(r[0])==dumps(env),'REPLAY','Old or conflicting advertisement')
            if provider_id!=self._identity():self._learn_route(provider_id,peer,env['body']['expires_at'])
            mid=digest('BTX/SWAPNET/AD-RELAY/2',env)
            if self._remember(mid,env['body']['expires_at']):
                for p in sorted(self.peers-{peer})[:8]:self.send(p,'swprov',dumps(env).decode())
            return
        wrapper=loads(raw);exact_fields(wrapper,{'packet','hops'});hops=integer(wrapper['hops'],hi=4)
        packet=wrapper['packet'];b=self._validate_packet(packet,command)
        self._learn_route(b['sender'],peer,b['expires_at'])
        mid=digest('BTX/SWAPNET/PACKET/2',packet)
        mine=b['recipient']==self._identity() or b['recipient']=='*'
        if b['sender']==self._identity():return
        if not mine:
            if hops and self._remember(mid,b['expires_at']):self._route(b['recipient'],command,packet,hops-1,peer)
            return
        if b['kind']=='ack':
            exact_fields(b['payload'],{'message_id'});self.journal.ack(b['payload']['message_id'],b['sender']);return
        seen=self.journal.seen(mid,b['expires_at'],self.now())
        if not seen:
            try:self._process(b)
            except Exception:
                self.journal.forget_message(mid);raise
        if b['recipient']!='*':self.emit(b['sender'],'ack',b['swap_id'],{'message_id':mid})
        if b['recipient']=='*' and hops and self._remember(mid,b['expires_at']):self._route('*',command,packet,hops-1,peer)
    def _process(self,b):
        kind,p,sid,sender=b['kind'],b['payload'],b['swap_id'],b['sender']
        if kind=='rfq':
            exact_fields(p,{'request_id','rfq'})
            require(digest('BTX/SWAPNET/RFQ/1',p['rfq'])==p['request_id'],'RFQ_BINDING','RFQ identifier mismatch')
            require(p['rfq']['requester']==digest('BTX/SWAPNET/REQUESTER/2',{'identity':sender,'nonce':p['rfq']['nonce']}),'RFQ_BINDING','Requester identity mismatch')
            for policy in self.markets():
                market=Market(**policy['market'])
                if (market.sell_asset,market.buy_asset)!=(p['rfq']['sell_asset'],p['rfq']['buy_asset']) or market.expires_at<=self.now():continue
                driver=self.coordinator._driver(market.buy_asset)
                maker=self._maker();maker.set_verified_inventory(market.buy_asset,str(driver.inventory()),self.now())
                quote=maker.quote(p['rfq'],market,self.now())
                self.emit(sender,'quote',sid,{'request_id':p['request_id'],'quote':quote.as_dict()});break
        elif kind=='quote':
            exact_fields(p,{'request_id','quote'});require(p['quote']['quote']['provider']==sender,'QUOTE_BINDING','Envelope signer is not quote provider')
            self.service.ingest_quote(p['quote'],p['request_id'])
        elif kind=='proposal':
            q=Quote.parse(p['quote']['quote'])
            policies=[m for m in self.markets() if (m['market']['sell_asset'],m['market']['buy_asset'])==(q.sell_asset,q.buy_asset)]
            require(policies,'MARKET_UNAVAILABLE','No authorized maker policy')
            self.coordinator.receive_proposal(sender,sid,p,policies[0])
        elif kind=='agreement':self.coordinator.receive_agreement(sender,sid,p)
        elif kind=='commit':self.coordinator.receive_commit(sender,sid,p)
        elif kind=='funded':self.coordinator.receive_reference(sender,sid,p)
        elif kind=='cancel':self.coordinator.receive_cancel(sender,sid,p)
        else:raise SwapError('MESSAGE_KIND','Unsupported message')
    def advertise(self):
        now=self.now();markets=[m for m in self.markets() if m['market']['expires_at']>now]
        if not markets:return {'advertised':False,'reason':'no_authorized_markets'}
        identity=self.identity.address();pairs=[]
        for m in markets:
            pair={'sell':m['market']['sell_asset'],'buy':m['market']['buy_asset']}
            if pair not in pairs:pairs.append(pair)
        body={'version':1,'network':self.network,'identity':identity,'sequence':self.journal.next_sequence(identity),
              'issued_at':now,'expires_at':now+600,'pairs':pairs,'settlement':['sha256-htlc-v1']}
        env={'body':body,'signature':self.identity.sign('BTX/SWAPNET/PROVIDER/1:'+digest('BTX/SWAPNET/PROVIDER/1',body))}
        self.service.catalog.ingest(env,now);self.journal.set_setting('own_advertisement',env)
        for peer in sorted(self.peers):self.send(peer,'swprov',dumps(env).decode())
        self._last_advertisement=now;return {'advertised':True,'identity':identity,'expires_at':now+600}
    def tick(self):
        now=self.now()
        if self.markets() and now-self._last_advertisement>=300:
            try:self.advertise()
            except SwapError as e:self.last_tick_error=e.as_dict()
        for mid,recipient,command,packet,attempt in self.journal.due(now):
            if packet['body']['expires_at']<=now:continue
            self._route(recipient,command,packet);self.journal.sent(mid,now)
            if packet['body']['kind'] in {'ack','rfq'}:self.journal.ack(mid,recipient)
        self.coordinator.tick()
        if now-self._last_maintenance>=60:
            self.journal.compact_outbox(now);self.routes={k:v for k,v in self.routes.items() if v[1]>now and v[0] in self.peers}
            self._last_maintenance=now
    def _context(self,ctx):
        caps={'read','quote','trade','audit'}
        if ctx.owner:caps|={'owner','maker'}
        return Context(ctx.name,frozenset(caps))
    def rpc(self,ctx,method,params=None):
        require(type(ctx) is Principal,'AUTH','Native authenticated context required')
        require(method in METHODS,'METHOD_NOT_FOUND','Unknown SwapNet RPC')
        p=params or {};require(type(p) is dict,'PARAMS','Expected request object')
        if METHODS[method] in {'owner','maker'}:self.authority.owner(ctx)
        function=getattr(self,'rpc_'+method,None)
        try:
            if function:return function(ctx,**p)
            return self.service.dispatch(self._context(ctx),method,p)
        except TypeError as e:raise SwapError('PARAMS','Unexpected or missing named field') from e
    def rpc_getswapnetworkinfo(self,ctx):
        with self.store.lock:n=self.store.db.execute('SELECT count(*) FROM providers WHERE expires>?',(self.now(),)).fetchone()[0]
        wallet=self.wallet_info() if self.wallet_info else {}
        return {'version':VERSION,'protocol':2,'network':self.network,'discovery_default':True,'peers':len(self.peers),
                'providers':n,'routes':len(self.routes),'automatic_spend_atoms':'0','in_process':True,
                'execution':'durable_htlc_coordinator','last_tick_error':self.last_tick_error,'packet_errors':self.packet_errors,
                'recent_packet_errors':self.recent_packet_errors,'wallet_loaded':wallet.get('wallet_loaded'),
                'wallet_warning':wallet.get('wallet_warning')}
    def rpc_getswapcapabilities(self,ctx):
        return {'methods':[{'name':k,'scope':v} for k,v in METHODS.items()],
                'assets':list(self.drivers),'settlement':['sha256-htlc-v1'],'partial_fills':False,'multihop_settlement':False}
    def rpc_listswapassets(self,ctx):
        out=[]
        for asset,d in self.drivers.items():
            try:d.ready();ready=True;reason=None
            except SwapError as e:ready=False;reason=e.code
            out.append({'asset':asset,'family':d.family,'ready':ready,'reason':reason})
        return {'assets':out,'unknown_assets_enabled':False}
    def rpc_requestswapquote(self,ctx,sell_asset,buy_asset,sell_atoms,nonce=None):
        from .assets import Asset
        Asset.parse(sell_asset);Asset.parse(buy_asset);atoms(sell_atoms,positive=True)
        require(sell_asset!=buy_asset,'PAIR','Different assets required')
        require('btx' in {Asset.parse(sell_asset).family,Asset.parse(buy_asset).family},'PAIR','Native BTX leg required')
        nonce=hex32(nonce or secrets.token_hex(32));identity=self.identity.address();now=self.now()
        b={'network':self.network,'requester':digest('BTX/SWAPNET/REQUESTER/2',{'identity':identity,'nonce':nonce}),
           'sell_asset':sell_asset,'buy_asset':buy_asset,'sell_atoms':sell_atoms,'nonce':nonce,'issued_at':now,'expires_at':now+120}
        rid=digest('BTX/SWAPNET/RFQ/1',b)
        with self.store.transaction() as db:
            db.execute('DELETE FROM rfqs WHERE expires<=?',(now,))
            require(db.execute('SELECT count(*) FROM rfqs').fetchone()[0]<256,'RFQ_LIMIT','RFQ limit reached')
            db.execute('INSERT OR IGNORE INTO rfqs VALUES(?,?,?,?)',(rid,now+120,ctx.name,dumps(b)))
        self.emit('*','rfq',rid,{'request_id':rid,'rfq':b})
        return {'request_id':rid,'requester':b['requester'],'expires_at':now+120,'peers':len(self.peers)}
    def rpc_acceptswapquote(self,ctx,quote_id,mandate_id,max_local_fee_atoms,refund_fee_atoms=None,claim_fee_atoms=None):
        with self.store.lock:
            row=self.store.db.execute('SELECT body FROM quotes WHERE id=?',(hex32(quote_id),)).fetchone()
            rfqs=self.store.db.execute('SELECT body FROM rfqs WHERE principal=?',(ctx.name,)).fetchall()
        require(row is not None,'QUOTE_MISSING','Quote is unavailable');env=loads(row[0]);q=Quote.parse(env['quote'])
        requests=[loads(r[0]) for r in rfqs if loads(r[0])['requester']==q.requester]
        require(requests,'FORBIDDEN','Quote belongs to another principal')
        # Half the total outgoing transaction-fee authorization is reserved for
        # refund recovery unless the owner supplies a smaller explicit cap.
        refund_fee_atoms=refund_fee_atoms or str(atoms(max_local_fee_atoms)//2)
        return self.coordinator.start(ctx,env,requests[0],hex32(mandate_id),max_local_fee_atoms,refund_fee_atoms,claim_fee_atoms)
    def rpc_createswapmandate(self,ctx,mandate):return {'mandate_id':self.authority.install(ctx,mandate)}
    def rpc_revokeswapmandate(self,ctx,mandate_id):
        self.authority.revoke(ctx,mandate_id);return {'revoked':True,'recovery_preserved':True}
    def rpc_getswap(self,ctx,swap_id):return self.coordinator.get(ctx,hex32(swap_id))
    def rpc_listswaps(self,ctx,limit=100):return {'swaps':self.coordinator.list(ctx,limit)}
    def rpc_resumeswap(self,ctx,swap_id):return self.coordinator.resume(ctx,hex32(swap_id))
    def rpc_refundswap(self,ctx,swap_id):return self.coordinator.request_refund(ctx,hex32(swap_id))
    def rpc_cancelswap(self,ctx,swap_id):return self.coordinator.cancel(ctx,hex32(swap_id))
    def rpc_getswaptranscript(self,ctx,swap_id):
        return {'swap':self.coordinator.get(ctx,swap_id),'operations':self.journal.operations(swap_id),
                'audit_head':self.store.verify_audit(),'secrets_included':False}
    def rpc_listswapoperations(self,ctx,swap_id):
        self.coordinator._owned(ctx,swap_id);return {'operations':self.journal.operations(swap_id)}
    def rpc_getswaprecoveryinfo(self,ctx,swap_id):
        _,s=self.coordinator._owned(ctx,swap_id)
        return {'swap_id':swap_id,'durable_recovery_ready':s['recovery_ready'],'secret_exposed':s['secret_exposed'],
                'refund_transaction_ready':bool(s.get('refund_op')),'evm_refund_intent_ready':bool(s.get('evm_refund_plan')),
                'raw_transactions_redacted':True}
    def rpc_getswaphealth(self,ctx):
        return {'audit_head':self.store.verify_audit(),'database_schema':2,'last_tick_error':self.last_tick_error,
                'pending_outbox':len(self.journal.due(self.now(),2048)),'sessions':len(self.journal.all())}
    def rpc_getswapbootstrapinfo(self,ctx):
        return {'mechanism':'existing_btx_peers','separate_seeds':False,'admitted_peers':len(self.peers),
                'fabricated_liquidity':False,'discovery':'active' if self.peers else 'awaiting_compatible_peer'}
    def rpc_getswaprouteinfo(self,ctx):
        return {'routes':[{'identity':k,'next_peer':v[0],'expires_at':v[1]} for k,v in sorted(self.routes.items())],
                'max_hops':4,'settlement_messages_signed':True,'preimages_on_peer_transport':False}
    def rpc_setswapmarket(self,ctx,market,mandate_id,max_local_fee_atoms,refund_fee_atoms,claim_fee_atoms,enabled=True):
        self.authority.owner(ctx);m=Market(**market);self.identity.address()
        require(type(enabled) is bool,'PARAMS','enabled must be boolean')
        with self.store.lock:r=self.store.db.execute('SELECT body,revoked FROM mandates WHERE id=?',(hex32(mandate_id),)).fetchone()
        require(r and not r[1] and loads(r[0])['principal']==ctx.name and loads(r[0])['asset']==m.buy_asset,'MANDATE_SCOPE','Maker mandate must cover local output asset and principal')
        for fee in (max_local_fee_atoms,refund_fee_atoms,claim_fee_atoms):atoms(fee,positive=True)
        require(atoms(refund_fee_atoms)<=atoms(max_local_fee_atoms),'FEE_CAP','Refund exceeds outgoing fee authorization')
        self.coordinator._driver(m.sell_asset).ready();self.coordinator._driver(m.buy_asset).ready()
        items=[x for x in self.markets() if (x['market']['sell_asset'],x['market']['buy_asset'])!=(m.sell_asset,m.buy_asset)]
        if enabled:items.append({'market':asdict(m),'mandate_id':mandate_id,'principal':ctx.name,'wallet':ctx.wallet,
                                'max_local_fee_atoms':max_local_fee_atoms,'refund_fee_atoms':refund_fee_atoms,'claim_fee_atoms':claim_fee_atoms})
        require(len(items)<=16,'MARKET_LIMIT','At most 16 exact-pair markets')
        self.journal.set_setting('markets',items)
        return self.advertise() if enabled else {'enabled':False,'remote_expiry_seconds':600}
    def rpc_listswapmarkets(self,ctx):return {'markets':[x for x in self.markets() if ctx.owner or x['principal']==ctx.name]}
    def rpc_publishswapprovider(self,ctx):self.authority.owner(ctx);return self.advertise()
    def rpc_withdrawswapprovider(self,ctx):
        self.authority.owner(ctx);self.journal.set_setting('markets',[]);self.journal.set_setting('own_advertisement',None)
        return {'withdrawn':True,'remote_expiry_seconds':600}
    def rpc_setswapassetpolicy(self,ctx,policy):
        self.authority.owner(ctx);require(self.configure_asset is not None,'ASSET_CONFIG','Native asset factory unavailable')
        asset=policy.get('asset');active=[s for _,_,s in self.journal.all() if s['stage'] not in {'cancelled','refunded','complete','rejected'}]
        require(not any(asset in (s.get('agreement',{}).get('long_leg',{}).get('asset'),s.get('agreement',{}).get('short_leg',{}).get('asset')) for s in active),
                'ASSET_BUSY','Cannot reconfigure an asset with active settlement obligations')
        driver=self.configure_asset(policy);driver.ready();self.drivers[asset]=driver
        policies=self.journal.setting('asset_policies',{});policies[asset]=policy;self.journal.set_setting('asset_policies',policies)
        return {'asset':asset,'ready':True}
    def rpc_listswapassetpolicies(self,ctx):
        policies=self.journal.setting('asset_policies',{})
        return {'policies':[{k:v for k,v in p.items() if k!='cookie_path'} for p in policies.values()]}
    def rpc_getswapwalletinfo(self,ctx):
        return self.wallet_info() if self.wallet_info else {'identity':self._identity(),'assets':list(self.drivers)}
    def rpc_exportswaprecovery(self,ctx,passphrase):
        self.authority.owner(ctx);require(self.export_recovery is not None,'BACKUP','Recovery exporter unavailable')
        return self.export_recovery(passphrase)
    def rpc_bumpswapfee(self,ctx,swap_id,kind,new_fee_atoms):
        from .fee_bump import bump
        return bump(self.coordinator,ctx,swap_id,kind,new_fee_atoms)
    def rpc_getswapevents(self,ctx,after=0,limit=100):
        integer(after);integer(limit,lo=1,hi=500)
        allowed={sid for sid,_,s in self.journal.all(None if ctx.owner else ctx.name)}
        with self.store.lock:rows=self.store.db.execute('SELECT seq,body,digest FROM audit WHERE seq>? ORDER BY seq LIMIT ?',(after,limit)).fetchall()
        events=[]
        for seq,raw,h in rows:
            body=loads(raw)
            if ctx.owner or body.get('swap_id',body.get('id')) in allowed:events.append({'sequence':seq,'event':body,'hash':h})
        return {'events':events,'next_sequence':rows[-1][0] if rows else after}
    def rpc_getswapvalidationinfo(self,ctx):
        return {'source_version':VERSION,'qualification_source':'package evidence/VALIDATION_REPORT.json',
                'runtime_observations_are_not_release_certification':True,'protocol_profile':'native-btx-btc-eth-htlc-v2'}
    def close(self):self.journal.checkpoint();self.store.close()
