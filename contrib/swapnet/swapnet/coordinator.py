"""Two-party HTLC execution, including restart/reorg/timeout recovery.

Long leg: initiator funds, responder claims. Short leg: responder funds,
initiator claims. Only independent local chain observations advance settlement.
"""
from dataclasses import asdict
import hashlib
import math
import secrets
import time
from .authorization import Principal,Grant
from .assets import Asset
from .canonical import atoms,hex32,hashlock,digest,exact_fields,integer
from .errors import require,SwapError
from .machine import Session,decide
from .policy import SafetyPolicy,Deadline
from .quote import Quote,SignedQuote
from .terms import Agreement,LegTerms

TERMINAL={'complete','refunded','cancelled','rejected'}

class Coordinator:
    def __init__(self,journal,authority,drivers,identity,vault,emit,*,clock=None,policy=None):
        self.journal,self.authority,self.drivers,self.identity,self.vault,self.emit=journal,authority,drivers,identity,vault,emit
        self.now=clock or (lambda:int(time.time()));self.policy=policy or SafetyPolicy();self._cursor=0;self._terminal_cursor=0
    def _driver(self,asset):
        require(asset in self.drivers,'ASSET_UNAVAILABLE','No qualified local chain driver for this asset')
        return self.drivers[asset]
    def _save(self,sid,s,rev):return self.journal.save(sid,s,rev)
    def _save_new(self,sid,body,ctx,budget_quote,mandate_id,maxfee):
        # Driver and vault setup has finished. Keep the debit, quote claim and
        # session in one transaction so failed initialization leaves no hold.
        with self.journal.store.transaction() as db:
            body['reservation_id']=self.authority.reserve(ctx,budget_quote,mandate_id,maxfee,db=db)
            self.journal.claim_quote(body['quote_id'],sid,db=db)
            self.journal.save(sid,body,-1,db=db)
    def _owned(self,ctx,sid):
        require(type(ctx) is Principal,'AUTH','Authenticated RPC principal required')
        rev,s=self.journal.load(sid)
        require(s['principal']==ctx.name or ctx.owner,'FORBIDDEN','Swap belongs to a different principal')
        return rev,s
    def _safe_view(self,sid,s):
        # No private key handles, signed raw transactions, PSBTs or preimages.
        keys=('role','stage','principal','peer','quote_id','agreement_id','secret_exposed','recovery_ready','funding_prepared',
              'funding_broadcast','created_at','updated_at','last_error','last_action','refs','observations','grant_id')
        out={'swap_id':sid,**{k:s[k] for k in keys if k in s}}
        if 'agreement' in s:out['agreement']=s['agreement']
        if s.get('recovery_facts',{}).get('mode')=='observation_only':
            f=s['recovery_facts'];out['recovery']={k:f[k] for k in
                ('mode','status','reason','original','checked_height','checked_at') if k in f}
            if f.get('last_verified'):
                out['recovery']['last_verified']={k:f['last_verified'][k] for k in
                    ('status','original','checked_height','checked_at') if k in f['last_verified']}
            out['recovery']['actions_enabled']=False
        return out
    def get(self,ctx,sid):return self._safe_view(sid,self._owned(ctx,sid)[1])
    def list(self,ctx,limit=100):
        require(type(ctx) is Principal,'AUTH','Authenticated principal required')
        return [self._safe_view(sid,s) for sid,rev,s in self.journal.all(None if ctx.owner else ctx.name,limit)]
    def _deadlines(self,a,b):
        ca,cb=a.clock(),b.clock();now=self.now();self.policy.check_clocks(now,ca,cb)
        target=max(21600,self.policy.reveal_margin_seconds*4)
        short=(Deadline('timestamp',cb.timestamp+target) if b.family=='evm' else
               Deadline('height',cb.height+math.ceil(target/cb.fastest_block_seconds)))
        _,worst=short.remaining(cb)
        # Headroom is planned into the long leg only. Validation stays a strict
        # settlement margin, so a later clock reading still has to clear it.
        span=self.policy.settlement_margin_seconds+self.policy.planning_headroom_seconds
        long=(Deadline('timestamp',ca.timestamp+worst+span) if a.family=='evm' else
              Deadline('height',ca.height+math.ceil((worst+span)/ca.fastest_block_seconds)))
        self.policy.validate_deadlines(long,short,ca,cb,now)
        if a.family=='evm':require(long.value-ca.timestamp<30*86400,'TIMEOUT_RANGE','Long lock exceeds contract duration')
        return long,short
    def start(self,ctx,envelope,rfq,mandate_id,max_local_fee_atoms,refund_fee_atoms,claim_fee_atoms=None):
        require(type(ctx) is Principal,'AUTH','Authenticated principal required')
        q=Quote.parse(envelope['quote']);now=self.now()
        identity=self.identity.address()
        requester=digest('BTX/SWAPNET/REQUESTER/2',{'identity':identity,'nonce':rfq['nonce']})
        SignedQuote(q,envelope['signature']).verify(self.identity.verify,q.network,requester,now)
        require(q.network==self.identity.network,'NETWORK','Quote targets a different BTX network')
        sid=digest('BTX/SWAPNET/SWAP/2',{'quote_id':q.id,'initiator':identity})
        try:return self.get(ctx,sid)
        except SwapError as e:
            if e.code!='NOT_FOUND':raise
        self.journal.ensure_capacity()
        a,b=self._driver(q.sell_asset),self._driver(q.buy_asset)
        a.ready();b.ready()
        self.authority.reserve(ctx,q,mandate_id,max_local_fee_atoms,check_only=True)
        long,short=self._deadlines(a,b)
        ak=a.new_key('refund');bk=b.new_key('claim')
        # A retry after interrupted setup reuses the already-created secret.
        secret_id='secret_'+sid
        if secret_id in self.vault.entries:
            h=hashlib.sha256(bytes.fromhex(self.vault.entries[secret_id]['preimage'])).hexdigest()
        else:h=self.vault.new_secret(sid)
        proposal={'quote':envelope,'rfq':rfq,'hashlock':h,'nonce':secrets.token_hex(32),
                  'long_refund_key':ak['public'],'long_refund_payout':ak['payout'],
                  'short_claim_key':bk['public'],'short_claim_payout':bk['payout'],
                  'long_deadline':asdict(long),'short_deadline':asdict(short),
                  'long_refund_fee_atoms':refund_fee_atoms,
                  'short_claim_fee_atoms':claim_fee_atoms or q.max_receive_network_fee_atoms}
        require(atoms(proposal['short_claim_fee_atoms'])<=atoms(q.max_receive_network_fee_atoms),'FEE_CAP','Claim fee exceeds signed quote')
        require(atoms(refund_fee_atoms)<=atoms(max_local_fee_atoms),'FEE_CAP','Refund fee exceeds local authorization')
        s={'principal':ctx.name,'wallet':ctx.wallet,'peer':q.provider,'role':'initiator','stage':'proposed',
           'quote_id':q.id,'quote':envelope,'proposal':proposal,
           'keys':{'refund':ak,'claim':bk},'max_local_fee_atoms':max_local_fee_atoms,
           'secret_exposed':False,'funding_prepared':False,'funding_broadcast':False,'recovery_ready':False,
           'refs':{},'created_at':now,'updated_at':now}
        self._save_new(sid,s,ctx,q,mandate_id,max_local_fee_atoms)
        self.emit(q.provider,'proposal',sid,proposal)
        return self._safe_view(sid,s)
    def receive_proposal(self,sender,sid,p,market):
        exact_fields(p,{'quote','rfq','hashlock','nonce','long_refund_key','long_refund_payout',
                        'short_claim_key','short_claim_payout','long_deadline','short_deadline',
                        'long_refund_fee_atoms','short_claim_fee_atoms'})
        q=Quote.parse(p['quote']['quote']);now=self.now();me=self.identity.address()
        require(q.network==self.identity.network and q.provider==me,'QUOTE_BINDING','Quote belongs to another maker/network')
        require(sid==digest('BTX/SWAPNET/SWAP/2',{'quote_id':q.id,'initiator':sender}),'SESSION_BINDING','Wrong swap id')
        requester=digest('BTX/SWAPNET/REQUESTER/2',{'identity':sender,'nonce':p['rfq']['nonce']})
        SignedQuote(q,p['quote']['signature']).verify(self.identity.verify,q.network,requester,now)
        require((q.sell_asset,q.buy_asset,q.sell_atoms)==(p['rfq']['sell_asset'],p['rfq']['buy_asset'],p['rfq']['sell_atoms']),
                'RFQ_BINDING','Quote differs from request')
        try:
            _,old=self.journal.load(sid)
            require(old['peer']==sender,'SESSION_BINDING','Session peer mismatch')
            if old['stage']=='offered':self.emit(sender,'agreement',sid,{'agreement':old['agreement'],'responder_signature':old['signatures']['responder']})
            return
        except SwapError as e:
            if e.code!='NOT_FOUND':raise
        self.journal.ensure_capacity()
        # market comes from a local, owner-authenticated persistent policy, not p.
        require(market['market']['sell_asset']==q.sell_asset and market['market']['buy_asset']==q.buy_asset,'MARKET','Market pair changed')
        require(now<market['market']['expires_at'],'MARKET_EXPIRED','Maker policy expired')
        from .marketmaker import Market
        pricing=Market(**market['market'])
        require(pricing.output(q.sell_atoms)==atoms(q.buy_atoms) and pricing.maker_fee_atoms==q.maker_fee_atoms,
                'MARKET_PRICE','Quoted price is not currently authorized')
        ctx=Principal(market['principal'],False,market.get('wallet',''))
        maxfee=market['max_local_fee_atoms']
        # Reverse quote solely represents the maker's own mandate debit; the
        # bilateral agreement remains bound to the original signed quote.
        reverse=Quote(q.network,sender,digest('BTX/SWAPNET/MAKER/2',{'swap_id':sid}),q.nonce,q.sequence,
                      q.buy_asset,q.sell_asset,str(atoms(q.buy_atoms)-atoms(q.maker_fee_atoms)),q.sell_atoms,'0','0',q.issued_at,q.expires_at)
        self.authority.reserve(ctx,reverse,market['mandate_id'],maxfee,check_only=True)
        a,b=self._driver(q.sell_asset),self._driver(q.buy_asset);a.ready();b.ready()
        long,short=Deadline(**p['long_deadline']),Deadline(**p['short_deadline'])
        self.policy.validate_deadlines(long,short,a.clock(),b.clock(),now)
        ak=a.new_key('claim');bk=b.new_key('refund')
        long_fee=market['claim_fee_atoms'];short_fee=market['refund_fee_atoms']
        h=hex32(p['hashlock'])
        la=LegTerms(q.sell_asset,q.sell_atoms,h,ak['public'],p['long_refund_key'],ak['payout'],p['long_refund_payout'],
                    long.domain,long.value,a.commitment(h,ak['public'],p['long_refund_key'],long.value),long_fee,p['long_refund_fee_atoms'])
        lb=LegTerms(q.buy_asset,str(atoms(q.buy_atoms)-atoms(q.maker_fee_atoms)),h,p['short_claim_key'],bk['public'],
                    p['short_claim_payout'],bk['payout'],short.domain,short.value,
                    b.commitment(h,p['short_claim_key'],bk['public'],short.value),p['short_claim_fee_atoms'],short_fee)
        agr=Agreement(q.network,q.id,sender,me,hex32(p['nonce']),la,lb)
        require(atoms(lb.max_claim_fee_atoms)<=atoms(q.max_receive_network_fee_atoms),'FEE_CAP','Claim fee changed')
        a.watch_terms(la,ak);b.watch_terms(lb,bk)
        sig=self.identity.sign(agr.signing_message)
        s={'principal':ctx.name,'wallet':ctx.wallet,'peer':sender,'role':'responder','stage':'offered',
           'quote_id':q.id,'quote':p['quote'],'proposal':p,
           'keys':{'refund':bk,'claim':ak},'max_local_fee_atoms':maxfee,'agreement':asdict(agr),'agreement_id':agr.id,
           'signatures':{'responder':sig},'secret_exposed':False,'funding_prepared':False,'funding_broadcast':False,
           'recovery_ready':False,'refs':{},'created_at':now,'updated_at':now}
        self._save_new(sid,s,ctx,reverse,market['mandate_id'],maxfee)
        self.emit(sender,'agreement',sid,{'agreement':asdict(agr),'responder_signature':sig})
    def receive_agreement(self,sender,sid,body):
        exact_fields(body,{'agreement','responder_signature'});rev,s=self.journal.load(sid)
        require(s['role']=='initiator' and s['peer']==sender and s['stage'] not in TERMINAL,'SESSION_BINDING','Unexpected agreement')
        agr=Agreement.parse(body['agreement']);p=s['proposal'];q=Quote.parse(s['quote']['quote'])
        if s.get('agreement_id'):
            require(s['agreement_id']==agr.id,'AGREEMENT_CHANGED','Committed agreement cannot be replaced')
            self.emit(sender,'commit',sid,{'agreement_id':agr.id,'signatures':s['signatures']})
            return
        require(agr.initiator==self.identity.address() and agr.responder==sender,'AGREEMENT_BINDING','Wrong counterparties')
        require(agr.nonce==p['nonce'] and agr.long_leg.hashlock==p['hashlock'],'AGREEMENT_BINDING','Secret/nonce changed')
        la,lb=agr.long_leg,agr.short_leg
        require((la.refund_key,la.refund_payout,lb.claim_key,lb.payout)==
                (p['long_refund_key'],p['long_refund_payout'],p['short_claim_key'],p['short_claim_payout']),
                'PAYOUT_CHANGED','Counterparty changed initiator-controlled keys or payouts')
        require((la.lock_domain,la.lock_value)==(p['long_deadline']['domain'],p['long_deadline']['value']) and
                (lb.lock_domain,lb.lock_value)==(p['short_deadline']['domain'],p['short_deadline']['value']),
                'TIMEOUT_CHANGED','Counterparty changed proposed deadlines')
        require(la.max_refund_fee_atoms==p['long_refund_fee_atoms'] and lb.max_claim_fee_atoms==p['short_claim_fee_atoms'],
                'FEE_CAP','Counterparty changed authorized fee limits')
        a,b=self._driver(la.asset),self._driver(lb.asset)
        a.verify_terms(la);b.verify_terms(lb)
        self.policy.validate_deadlines(Deadline(la.lock_domain,la.lock_value),Deadline(lb.lock_domain,lb.lock_value),a.clock(),b.clock(),self.now())
        require(self.identity.verify(sender,body['responder_signature'],agr.signing_message),'BAD_SIGNATURE','Maker agreement signature invalid')
        sigs={'initiator':self.identity.sign(agr.signing_message),'responder':body['responder_signature']}
        agr.verify(q,sigs,self.identity.verify)
        a.watch_terms(la,s['keys']['refund']);b.watch_terms(lb,s['keys']['claim'])
        s.update(agreement=asdict(agr),agreement_id=agr.id,signatures=sigs,stage='committed',updated_at=self.now())
        s['grant_id']=self._grant(sid,s,agr);self._save(sid,s,rev)
        self.emit(sender,'commit',sid,{'agreement_id':agr.id,'signatures':sigs})
    def receive_commit(self,sender,sid,body):
        exact_fields(body,{'agreement_id','signatures'});rev,s=self.journal.load(sid)
        require(s['role']=='responder' and s['peer']==sender and s['stage'] not in {'cancelled','rejected'},'SESSION_BINDING','Unexpected commit')
        agr=Agreement.parse(s['agreement']);require(body['agreement_id']==agr.id,'AGREEMENT_BINDING','Wrong commit')
        agr.verify(Quote.parse(s['quote']['quote']),body['signatures'],self.identity.verify)
        if s['stage']!='offered':return
        s.update(signatures=body['signatures'],stage='committed',updated_at=self.now())
        s['grant_id']=self._grant(sid,s,agr);self._save(sid,s,rev)
    def _grant(self,sid,s,agr):
        own=agr.long_leg if s['role']=='initiator' else agr.short_leg
        incoming=agr.short_leg if s['role']=='initiator' else agr.long_leg
        g=Grant(s['principal'],sid,agr.id,s['reservation_id'],own.asset,own.amount_atoms,s['max_local_fee_atoms'],
                own.lock_commitment,own.refund_payout,incoming.payout,self.authority.reservation_expiry(s['reservation_id']))
        return self.authority.grant(Principal(s['principal'],False,s.get('wallet','')),g)
    def receive_reference(self,sender,sid,body):
        exact_fields(body,{'agreement_id','leg','reference'});rev,s=self.journal.load(sid)
        require(s['peer']==sender and s.get('agreement_id')==body['agreement_id'],'SESSION_BINDING','Wrong funding receipt')
        expected='b' if s['role']=='initiator' else 'a'
        require(body['leg']==expected,'LEG_SCOPE','Peer cannot supply local funding reference')
        ref=body['reference'];require(type(ref) is dict,'REFERENCE','Invalid transaction reference')
        agr=Agreement.parse(s['agreement']);leg=agr.short_leg if expected=='b' else agr.long_leg
        if Asset.parse(leg.asset).family in {'btx','btc'}:
            exact_fields(ref,{'txid','vout'});hex32(ref['txid']);integer(ref['vout'],hi=0xffffffff)
        else:
            exact_fields(ref,{'txid','lock_id','salt'});hex32(ref['txid'].removeprefix('0x'));hex32(ref['lock_id']);hex32(ref['salt'])
            self._driver(leg.asset).verify_reference(sid,leg,ref)
        if expected in s['refs']:
            require(s['refs'][expected]==ref,'FUNDING_REPLACED','Counterparty attempted to change funding reference');return
        s['refs'][expected]=ref;s['updated_at']=self.now();self._save(sid,s,rev)
    def cancel(self,ctx,sid):
        rev,s=self._owned(ctx,sid)
        require(not self._imported_unknown(sid,s),'RECOVERY_READ_ONLY','Imported payment state is unresolved')
        require(not s['funding_prepared'] and not s['funding_broadcast'],'FUNDS_LOCKED','Prepared/funded swaps require refund recovery')
        if s['stage']=='cancelled':return self._safe_view(sid,s)
        self.journal.store.settle_reservation(s['reservation_id'],'0')
        s['stage']='cancelled';s['updated_at']=self.now();self._save(sid,s,rev)
        self.emit(s['peer'],'cancel',sid,{'quote_id':s['quote_id']})
        return self._safe_view(sid,s)
    def receive_cancel(self,sender,sid,body):
        rev,s=self.journal.load(sid);require(s['peer']==sender,'SESSION_BINDING','Wrong cancelling peer')
        if not s['funding_prepared'] and s['stage'] not in TERMINAL:self.cancel(Principal(s['principal']),sid)
    def _persist_prepared(self,sid,asset,kind,prepared):
        return self.journal.prepare(sid,asset,kind,prepared.txid,prepared.raw,
                                    {**prepared.metadata,'reference':prepared.reference,'fee_atoms':prepared.fee_atoms})
    def _own(self,s,agr):
        return (('a',agr.long_leg,'b',agr.short_leg) if s['role']=='initiator' else ('b',agr.short_leg,'a',agr.long_leg))
    def _prepare(self,sid,s,rev,agr):
        self._require_effect(sid,s)
        own_name,own,incoming_name,incoming=self._own(s,agr)
        driver=self._driver(own.asset);incoming_driver=self._driver(incoming.asset)
        if s['role']=='responder' and 'claim_template' not in s:
            s['claim_template']=incoming_driver.prepare_claim_template(sid,incoming,s['refs'][incoming_name],s['keys']['claim'])
            rev=self._save(sid,s,rev)
        self.authority.check(s['grant_id'],agr.id,kind='fund',asset=own.asset,amount_atoms=own.amount_atoms,
                             fee_atoms=s['max_local_fee_atoms'],funding_script=own.lock_commitment)
        # The operation WAL is the recovery authority if a crash happened after a
        # signed transaction was committed but before its session pointer was saved.
        prior=[o for o in self.journal.operations(sid,private=True) if o['kind']=='fund' and o['asset']==own.asset]
        require(len(prior)<=1,'RECOVERY_CONFLICT','Multiple prepared funding records; refuse alternate spend')
        adopted=None
        if prior:
            from .drivers import Prepared
            op=prior[0];m=op['metadata']
            funded=Prepared(op['txid'],op['raw'],m['reference'],m['fee_atoms'],m)
        else:
            from .funding_scan import find_funding_output
            # A committed restore has no funding record. Adopt an exact unspent
            # lock, or the EVM lock already stored under its deterministic id,
            # instead of building a second one. A failed lookup raises.
            adopted=find_funding_output(driver,own,sid, recover_history=(
                driver.family == 'btc' and self.journal.setting('restored_session:'+sid, False)))
            if adopted:
                if 'lock_id' in adopted:
                    ref={'txid':adopted['txid'],'lock_id':adopted['lock_id'],'salt':adopted['salt']}
                    funded=None
                else:
                    ref={'txid':adopted['txid'],'vout':adopted['vout']}
                    if adopted.get('raw'):
                        from .drivers import Prepared
                        funded=Prepared(adopted['txid'],adopted['raw'],ref,'0',{'adopted_output':True})
                    else:
                        funded=None
            else:
                funded=driver.prepare_funding(sid,own,s['keys']['refund'],s['reservation_id'],s['max_local_fee_atoms'])
        # No broadcast until BOTH immutable funding and refund records are durable.
        # An adopted output has no new funding transaction to persist or broadcast.
        if funded is not None:
            s['fund_op']=self._persist_prepared(sid,own.asset,'fund',funded)
            s['refs'][own_name]=funded.reference
        else:
            s['refs'][own_name]=ref
        funding_fee=funded.fee_atoms if funded is not None else '0'
        self.authority.check(s['grant_id'],agr.id,kind='refund',asset=own.asset,
                             fee_atoms=own.max_refund_fee_atoms,destination=own.refund_payout)
        if driver.family=='evm':
            s['evm_refund_plan']=driver.refund_plan(sid,own,s['refs'][own_name],s['keys']['refund'],str(atoms(s['max_local_fee_atoms'])-atoms(funding_fee)))
        else:
            previous=[o for o in self.journal.operations(sid,private=True) if o['kind']=='refund' and o['asset']==own.asset]
            if previous:
                from .drivers import Prepared
                op=previous[-1];m=op['metadata'];refund=Prepared(op['txid'],op['raw'],m['reference'],m['fee_atoms'],m)
            else:refund=driver.prepare_refund(sid,own,s['refs'][own_name],s['keys']['refund'])
            require(atoms(funding_fee)+atoms(refund.fee_atoms)<=atoms(s['max_local_fee_atoms']),
                    'FEE_CAP','Combined funding/refund exposure exceeds local fee budget')
            s['refund_op']=self._persist_prepared(sid,own.asset,'refund',refund)
        s.update(funding_prepared=True,recovery_ready=True,stage='prepared',updated_at=self.now())
        if adopted:
            s['funding_broadcast']=True
            s['stage']='funded'
            self.authority.mark_consumed(s['grant_id'])
            self.emit(s['peer'],'funded',sid,{'agreement_id':agr.id,'leg':own_name,'reference':s['refs'][own_name]})
        rev=self._save(sid,s,rev);self.journal.checkpoint();return rev
    def _fund(self,sid,s,rev,agr):
        self._require_effect(sid,s)
        own_name,own,_,_=self._own(s,agr)
        require(s.get('fund_op') and (s.get('refund_op') or s.get('evm_refund_plan')) and s['recovery_ready'],'RECOVERY_MISSING','Durable refund missing')
        # Consumption is durable before bytes can escape. Revocation cannot cancel
        # this already-prepared recovery obligation or cause alternate funding.
        if not self.authority.permit_existing_funding(s['grant_id']):
            self.authority.check(s['grant_id'],agr.id,kind='fund',asset=own.asset,
                                 amount_atoms=own.amount_atoms,fee_atoms=s['max_local_fee_atoms'],funding_script=own.lock_commitment)
        # Persist the authenticated reference before funding can escape. It is only
        # a hint: the counterparty still reads and validates its own full node.
        self.emit(s['peer'],'funded',sid,{'agreement_id':agr.id,'leg':own_name,'reference':s['refs'][own_name]})
        self.authority.mark_consumed(s['grant_id'])
        self.journal.broadcast(s['fund_op'],self._driver(own.asset))
        s.update(funding_broadcast=True,stage='funded',updated_at=self.now());rev=self._save(sid,s,rev)
        self.emit(s['peer'],'funded',sid,{'agreement_id':agr.id,'leg':own_name,'reference':s['refs'][own_name]})
        return rev
    def _claim(self,sid,s,rev,agr):
        self._require_effect(sid,s)
        _,_,incoming_name,incoming=self._own(s,agr);driver=self._driver(incoming.asset)
        if 'claim_template' not in s:
            s['claim_template']=driver.prepare_claim_template(sid,incoming,s['refs'][incoming_name],s['keys']['claim'])
            rev=self._save(sid,s,rev)
        secret=(self.vault.secret(sid,incoming.hashlock) if s['role']=='initiator' else
                self.vault.secret(sid,incoming.hashlock))
        if not s['secret_exposed']:
            s['secret_exposed']=True;s['stage']='secret_exposed';rev=self._save(sid,s,rev);self.journal.checkpoint()
        if not s.get('claim_op'):
            previous=[o for o in self.journal.operations(sid,private=True) if o['kind']=='claim' and o['asset']==incoming.asset]
            if previous:
                from .drivers import Prepared
                op=previous[-1];m=op['metadata'];claim=Prepared(op['txid'],op['raw'],m['reference'],m['fee_atoms'],m)
            else:claim=driver.finish_claim(incoming,s['refs'][incoming_name],s['claim_template'],secret)
            s['claim_op']=self._persist_prepared(sid,incoming.asset,'claim',claim);rev=self._save(sid,s,rev)
        self.journal.broadcast(s['claim_op'],driver)
        s['stage']='claim_broadcast';s['updated_at']=self.now();return self._save(sid,s,rev)
    def _imported_unknown(self,sid,s):
        if s.get('recovery_facts',{}).get('mode')=='observation_only':return True
        if (not self.journal.setting('restored_session:'+sid,False)
                or s.get('stage')!='committed' or not s.get('agreement')):return False
        agr=Agreement.parse(s['agreement']);name,own,_,_=self._own(s,agr)
        if Asset.parse(own.asset).family!='btc':return False
        if (s.get('funding_prepared') or s.get('funding_broadcast') or s.get('recovery_ready')
                or s['refs'].get(name)):return False
        return not any(o['asset']==own.asset and o['kind'] in {'fund','refund'}
                       for o in self.journal.operations(sid))
    def _observation_only(self,sid,s):
        if s.get('recovery_facts',{}).get('mode')=='observation_only':return True
        if not self._imported_unknown(sid,s):return False
        agr=Agreement.parse(s['agreement']);_,own,_,_=self._own(s,agr)
        clock=self._driver(own.asset).clock();self.policy.check_clocks(self.now(),clock)
        return own.lock_domain=='height' and clock.height>=own.lock_value
    def _require_effect(self,sid,s):
        require(not self._observation_only(sid,s),'RECOVERY_READ_ONLY',
                'Expired restored session is observation-only')
    def _discover_only(self,sid,s,rev,agr):
        from .funding_scan import find_funding_output
        from .adapters import to_atoms
        name,own,_,_=self._own(s,agr);driver=self._driver(own.asset)
        old=s.get('recovery_facts',{})
        require(not old or old.get('agreement_id')==agr.id,'RECOVERY_CONFLICT','Recovery agreement changed')
        if not old:
            old={'mode':'observation_only','agreement_id':agr.id,'status':'unresolved',
                 'reason':'EXPIRED_BACKUP_READ_ONLY'}
            s['recovery_facts']=old;s['last_action']='read_only_recovery'
            rev=self._save(sid,s,rev) # Fail before I/O; never fall through to spending.
        facts=dict(old)
        try:
            clock=driver.clock();self.policy.check_clocks(self.now(),clock)
            facts['checked_height']=clock.height
            ref=facts.get('original')
            if ref is None:
                ref=find_funding_output(driver,own,sid,recover_history=True)
                require(ref is not None,'RECOVERY_UNRESOLVED','Original payment is unresolved')
                facts['original']={'txid':ref['txid'],'vout':ref['vout']}
            report=driver.observe(own,facts['original']);obs=report.observation
            self.policy.check_clocks(self.now(),report.clock)
            if not obs.present:
                facts.update(status='unresolved',reason='ORIGINAL_UNAVAILABLE')
            elif not obs.exact_terms or not obs.canonical or obs.conflicting:
                facts.update(status='conflicting',reason='ORIGINAL_CONFLICT')
            elif (obs.claimed or obs.refunded) and obs.settled(driver.family,self.policy,self.now()):
                facts.update(status='original_claimed' if obs.claimed else 'original_refunded',
                             reason='EXPIRED_BACKUP_READ_ONLY')
            else:
                coin=driver.rpc('gettxout',ref['txid'],ref['vout'],True)
                if coin:
                    require(coin['scriptPubKey']['hex']==own.lock_commitment
                            and to_atoms(coin['value'])==atoms(own.amount_atoms),
                            'RECOVERY_CONFLICT','Live output changed')
                facts.update(status='original_unspent' if coin else 'spend_lookup_pending',
                             reason='EXPIRED_BACKUP_READ_ONLY')
        except SwapError as error:
            facts.update(status='unresolved',reason=error.code)
        if facts.get('status') in {'original_unspent','original_claimed','original_refunded'}:
            verified={k:facts[k] for k in ('status','original','checked_height') if k in facts}
            previous=old.get('last_verified',{})
            if verified!={k:v for k,v in previous.items() if k!='checked_at'}:
                verified['checked_at']=self.now();facts['last_verified']=verified
        if facts!=old:
            facts['checked_at']=self.now();s['recovery_facts']=facts
            s['last_action']='read_only_recovery';self._save(sid,s,rev)
        # No normal execution refs/flags, secret, operation or financial mutation.

    def tick_one(self,sid):
        rev,s=self.journal.load(sid)
        if s['stage'] in {'proposed','offered'}:
            # Sessions before commitment expire without funding; release held budget.
            q=Quote.parse(s['quote']['quote'])
            if self.now()>q.expires_at+600:
                self.cancel(Principal(s['principal']),sid)
            return
        if s['stage'] in {'cancelled','rejected'} or 'agreement' not in s:return
        agr=Agreement.parse(s['agreement'])
        if self._observation_only(sid,s):
            self._discover_only(sid,s,rev,agr);return
        a,b=self._driver(agr.long_leg.asset),self._driver(agr.short_leg.asset)
        # The counterparty leg must not block a mature local refund or claim.
        ra=self._observe(a,agr.long_leg,s['refs'].get('a'),required=s['role']=='initiator')
        try:
            rb=self._observe(b,agr.short_leg,s['refs'].get('b'),required=s['role']=='responder')
        except SwapError as error:
            unavailable=error.code=='RPC_COOKIE' and error.message=='RPC cookie unavailable'
            if not unavailable or not self._refund_without_bitcoin(sid,s,rev,agr,a,ra):
                raise
            return
        # Valid preimages read from either local chain remain public forever,
        # even if the revealing transaction later leaves the canonical chain.
        for report in (ra,rb):
            if report.preimage:
                secret=bytes.fromhex(report.preimage)
                require(hashlock(secret)==agr.long_leg.hashlock,'PREIMAGE','Chain preimage does not match agreement')
                key='secret_'+sid
                if key not in self.vault.entries:
                    self.vault.entries[key]={'swap_id':sid,'preimage':secret.hex()};self.vault.save()
                if not s['secret_exposed']:s['secret_exposed']=True;s['stage']='secret_exposed';rev=self._save(sid,s,rev)
        state=Session(sid,s['role'],s['stage'],True,s['secret_exposed'],s['funding_prepared'],s['funding_broadcast'],s['recovery_ready'])
        action=decide(state,ra.observation,rb.observation,ra.clock,rb.clock,
                      Deadline(agr.long_leg.lock_domain,agr.long_leg.lock_value),Deadline(agr.short_leg.lock_domain,agr.short_leg.lock_value),self.policy,self.now())
        s['last_action']=action;s['last_error']=None;s['observations']={'a':asdict(ra.observation),'b':asdict(rb.observation)}
        s['updated_at']=self.now()
        if (action == 'wait_for_chain' and s['role'] == 'responder' and s['stage'] == 'committed'
                and not rb.observation.present
                and ra.observation.refunded
                and ra.observation.settled(ra.clock.family, self.policy, self.now())
                and self.journal.close_unfunded_responder(sid, s, rev)):
            # No local funds can need recovery. Cancelling also prevents a
            # later remote reorg from authorizing funding on this agreement.
            return
        rev=self._save(sid,s,rev)
        if action in {'prepare_long_funding_and_recovery','prepare_short_funding_and_recovery'}:
            self._prepare(sid,s,rev,agr)
        elif action in {'broadcast_prepared_long_funding','broadcast_prepared_short_funding'}:
            self._fund(sid,s,rev,agr)
        elif action in {'persist_secret_exposure_then_claim_short_leg','claim_long_leg','rebroadcast_short_claim'}:
            self._claim(sid,s,rev,agr)
        elif action=='refund_local_leg':
            _,own,_,_=self._own(s,agr)
            if not s.get('refund_op') and s.get('evm_refund_plan'):
                prepared=self._driver(own.asset).materialize_refund(s['evm_refund_plan'])
                s['refund_op']=self._persist_prepared(sid,own.asset,'refund',prepared);rev=self._save(sid,s,rev)
            require(s.get('refund_op'),'RECOVERY_MISSING','No durable refund transaction')
            self.journal.broadcast(s['refund_op'],self._driver(own.asset))
            s['stage']='refund_broadcast';self._save(sid,s,rev)
        elif action in {'complete','refunded'}:
            _,own,_,incoming=self._own(s,agr)
            received=own if action=='refunded' else incoming
            receiver=self._driver(received.asset)
            if receiver.family=='evm':
                localkey=s['keys']['refund' if action=='refunded' else 'claim']
                if not receiver.ensure_withdrawal(sid,received,localkey,refund=action=='refunded'):
                    s['stage']='withdrawing';self._save(sid,s,rev);return
            s['stage']=action;self._save(sid,s,rev);self.authority.terminal(s['grant_id'])
        elif action=='freeze_and_reconcile':
            s['stage']='reconciling';self._save(sid,s,rev)
        elif action=='reconcile_existing_funding' and s.get('fund_op'):
            own_name,own,_,_=self._own(s,agr)
            report=ra if own_name=='a' else rb
            if not report.observation.present:self.journal.broadcast(s['fund_op'],self._driver(own.asset))
            # Repeat a lost receipt after restart/reconnection; recipients deduplicate.
            if self.now()-s.get('last_receipt',0)>=30:
                self.emit(s['peer'],'funded',sid,{'agreement_id':agr.id,'leg':own_name,'reference':s['refs'][own_name]})
                s['last_receipt']=self.now();self._save(sid,s,rev)
        elif s['stage'] in {'complete','refunded'}:
            # Continue observing terminal sessions. A deep reorg reopens recovery,
            # but does not replenish a consumed mandate or erase secret exposure.
            s['stage']='reconciling';self._save(sid,s,rev)
    def _refund_without_bitcoin(self,sid,s,rev,agr,driver,report):
        # Limit offline recovery to the original, authorized BTX refund before
        # the counterparty leg was recorded or the secret was exposed.
        own=agr.long_leg
        if (s['role']!='initiator' or driver.family!='btx' or not agr.short_leg.asset.startswith('btc:')
                or own.lock_domain!='height' or s['secret_exposed'] or s['refs'].get('b')
                or s.get('observations',{}).get('b',{}).get('conflicting')
                or not (s['funding_prepared'] and s['funding_broadcast'] and s['recovery_ready'] and s.get('refund_op'))):
            return False
        now=self.now()
        self.policy.check_clocks(now,report.clock)
        obs=report.observation
        if (report.clock.height<own.lock_value or obs.claimed
                or not obs.settled(driver.family,self.policy,now)):
            return False
        op=next((item for item in self.journal.operations(sid,private=True) if item['id']==s['refund_op']),None)
        require(op and op['kind']=='refund' and op['asset']==own.asset
                and op['metadata'].get('reference')==s['refs']['a'],'RECOVERY_CONFLICT','Saved refund does not match local funding')
        if obs.refunded:
            tx=driver.rpc('getrawtransaction',op['txid'],True)
            if tx.get('confirmations',0)<self.policy.confirmations(driver.family):
                return False
            if s['stage']=='refunded':
                # Stage persistence can precede terminal budget cleanup across a crash.
                # Retry the idempotent cleanup after revalidating the local refund.
                self.authority.terminal(s['grant_id'])
                return True
            s['stage']='refunded'
        else:
            if s['stage']=='refund_broadcast' and driver.has_transaction(op['txid']):
                return True
            ref=s['refs']['a']
            coin=driver.rpc('gettxout',ref['txid'],ref['vout'],True)
            if not coin or coin['bestblock']!=driver.rpc('getbestblockhash'):
                return False
            require(coin['scriptPubKey']['hex']==own.lock_commitment,'RECOVERY_CONFLICT','Local refund output changed')
            self.journal.broadcast(s['refund_op'],driver)
            s['stage']='refund_broadcast'
        s.update(last_action='refund_local_leg',last_error=None,updated_at=now)
        s.setdefault('observations',{})['a']=asdict(obs)
        self._save(sid,s,rev)
        if s['stage']=='refunded':
            self.authority.terminal(s['grant_id'])
        return True

    def _observe(self,driver,terms,ref,*,required):
        try:return driver.observe(terms,ref)
        except SwapError:
            if required:raise
            from .drivers import Report
            from .machine import LegObservation
            return Report(LegObservation(observed_at=self.now()),driver.clock())
    def tick(self):
        # Bounded work per pass; terminal sessions remain monitored for deep reorgs.
        rows=self.journal.all(limit=4096)
        if not rows:return
        active=[r for r in rows if r[2]['stage'] not in TERMINAL]
        terminal=[r for r in rows if r[2]['stage'] in {'complete','refunded'}]
        selected=[]
        if active:
            start=self._cursor % len(active);selected=(active+active)[start:start+min(4,len(active))]
            self._cursor=(start+len(selected)) % len(active)
        if terminal:
            selected.append(terminal[self._terminal_cursor % len(terminal)])
            self._terminal_cursor+=1
        for sid,_,s in selected:
            try:self.tick_one(sid)
            except SwapError as e:
                rev,current=self.journal.load(sid)
                current['last_error']={'code':e.code,'message':e.message};current['updated_at']=self.now()
                self._save(sid,current,rev)
    def resume(self,ctx,sid):
        self._owned(ctx,sid);self.tick_one(sid);return self.get(ctx,sid)
    def request_refund(self,ctx,sid):
        _,s=self._owned(ctx,sid)
        self._require_effect(sid,s)
        require(s['funding_prepared'],'NOT_FUNDED','Swap has no prepared funding')
        agr=Agreement.parse(s['agreement']);_,own,_,_=self._own(s,agr);clock=self._driver(own.asset).clock()
        mature=(clock.height>=own.lock_value if own.lock_domain=='height' else clock.timestamp>=own.lock_value)
        require(mature,'REFUND_EARLY','Refund timelock has not matured')
        return self.resume(ctx,sid)
