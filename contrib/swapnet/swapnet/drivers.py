"""Operational BTX/Bitcoin drivers used by the native in-process coordinator.

RPC URLs and key handles are local owner state; peer messages contain neither.
Every funding output, input amount, change script, and spending branch is checked
before signing. Counterparty hints only identify a transaction to independently
read from the relevant full node.
"""
from dataclasses import dataclass,asdict
from decimal import Decimal
import hashlib
import math
import statistics
import time
from .assets import Asset
from .adapters import BTXAdapter,BitcoinAdapter,UtxoLock,create_funded_psbt,to_atoms,coin_string
from .bitcoin import Transaction,build_spend,sign_digest,TxInput,TxOutput,parse_htlc_script
from .canonical import atoms,hex32,integer,hashlock,digest
from .errors import require,SwapError
from .machine import LegObservation
from .policy import ChainClock
from .plans import FundingPlan
from .psbt import add_witness_utxo

@dataclass(frozen=True)
class Prepared:
    txid:str
    raw:str
    reference:dict
    fee_atoms:str
    metadata:dict

@dataclass(frozen=True)
class Report:
    observation:LegObservation
    clock:ChainClock
    preimage:str|None=None
    blockhash:str=''

class UTXODriver:
    def __init__(self,asset,rpc,wallet,watch,journal,vault,*,network,hrp=None,fee_rate=2,
                 confirmations=None,clock=None):
        self.asset=Asset.parse(asset);require(self.asset.family in {'btx','btc'},'CHAIN','UTXO chain required')
        self.rpc,self.wallet,self.watch,self.journal,self.vault=rpc,wallet,watch,journal,vault
        self.network=network;self.now=clock or (lambda:int(time.time()))
        self.fee_rate=integer(fee_rate,lo=1,hi=10000)
        self.confirmations=confirmations or (20 if self.asset.family=='btx' else 6)
        self.adapter=(BTXAdapter(rpc,wallet,self.asset.genesis) if self.asset.family=='btx'
                      else BitcoinAdapter(rpc,wallet,self.asset.genesis,hrp or 'bc'))
    @property
    def family(self):return self.asset.family
    def ready(self):
        self.adapter.check_chain();info=self.wallet('getwalletinfo')
        require(info.get('private_keys_enabled',True),'WALLET_READONLY','Funding wallet cannot sign')
        return True
    def clock(self):
        now=self.now();self.adapter.check_chain();height=self.rpc('getblockcount');tip=self.rpc('getbestblockhash')
        header=self.rpc('getblockheader',tip)
        # Planning uses the chain's target spacing, not the last 24 headers.
        # A stall must not shrink the long-leg height, and a one-second sample
        # must not demand hundreds of thousands of blocks. Half the target is
        # the fast bound; twice the target is the slow bound.
        target=600 if self.family=='btc' else 90
        fastest,slowest=target//2,target*2
        return ChainClock(self.family,height,header.get('mediantime',header['time']),now,
                          fastest,slowest,now-header['time']>max(7200,target*12))
    def inventory(self):
        self.adapter.check_chain()
        coins=self.wallet('listunspent',self.confirmations,9999999)
        return sum(to_atoms(c['amount']) for c in coins if c.get('spendable') and c.get('safe',True))
    def new_key(self,role):
        require(role in {'claim','refund'},'KEY_ROLE','Unknown contract key role')
        if self.family=='btx':
            address=self.wallet('getnewaddress','swapnet-'+role,'p2mr')
            pub=self.wallet('exportpqkey',address)['pubkey']
            require(len(pub)==2624,'BTX_KEY','Expected ML-DSA-44 key')
            return {'public':pub,'handle':address,'payout':self.wallet('getnewaddress','swapnet-payout','p2mr'),'role':role}
        kid=self.vault.create_key('btc',self.asset.genesis,role)
        pub=self.vault.public_key(kid,family='btc',genesis=self.asset.genesis,role=role).hex()
        return {'public':pub,'handle':kid,'payout':self.wallet('getnewaddress','swapnet-payout','bech32'),'role':role}
    def contract(self,terms):
        require(terms.asset==self.asset.id,'CHAIN','Terms for a different chain')
        if self.family=='btx':
            return self.adapter.descriptor(terms.hashlock,terms.claim_key,terms.refund_key,terms.lock_value)
        return self.adapter.contract(terms.hashlock,bytes.fromhex(terms.claim_key),bytes.fromhex(terms.refund_key),terms.lock_value)
    def commitment(self,hashlock_,claim,refund,deadline):
        if self.family=='btx':return self.adapter.descriptor(hashlock_,claim,refund,deadline)['script_pubkey']
        return self.adapter.contract(hashlock_,bytes.fromhex(claim),bytes.fromhex(refund),deadline)['script_pubkey']
    def verify_terms(self,terms):
        c=self.contract(terms)
        require(c['script_pubkey']==terms.lock_commitment,'SCRIPT_MISMATCH','Contract script differs from signed agreement')
        for dest in (terms.payout,terms.refund_payout):
            require(self.rpc('validateaddress',dest).get('isvalid') is True,'PAYOUT','Invalid chain payout address')
        return c
    def watch_terms(self,terms,local_key=None):
        c=self.verify_terms(terms)
        if self.family=='btx' and local_key:
            # Implemented by src/swapnet/wallet_bridge.cpp. Private providers are
            # merged inside CWallet; no pqhd seed or private descriptor is exported.
            self.wallet('_swapnet_import_htlc',terms.hashlock,terms.claim_key,terms.refund_key,
                        terms.lock_value,local_key['handle'])
        else:
            desc='addr('+c['address']+')'
            info=self.rpc('getdescriptorinfo',desc)
            checked=desc+'#'+info['checksum']
            result=self.watch('importdescriptors',[{'desc':checked,'timestamp':'now','active':False}])
            require(result and result[0].get('success') is True,'WATCH_FAILED','HTLC watch import failed')
        return c
    def _owned(self,script,address=None):
        if address:
            info=self.wallet('getaddressinfo',address)
            return info.get('ismine') is True and info.get('scriptPubKey')==script
        # Native decode usually supplies an address. Fall back to decodescript.
        info=self.rpc('decodescript',script);a=info.get('address')
        return bool(a and self._owned(script,a))
    def prepare_funding(self,sid,terms,local_key,reservation_id,max_fee_atoms):
        c=self.watch_terms(terms,local_key);self.ready()
        result=create_funded_psbt(self.wallet,[],[{c['address']:coin_string(atoms(terms.amount_atoms))}],0,
                           {'lockUnspents':True,'replaceable':False,'include_unsafe':False,
                            'fee_rate':self.fee_rate,'minconf':self.confirmations},True,
                           request_v0=self.family=='btc')
        fee=to_atoms(result['fee']);require(0<=fee<=atoms(max_fee_atoms),'FEE_CAP','Funding fee exceeds authorization')
        psbt=self.rpc('decodepsbt',result['psbt'])
        decoded=psbt.get('tx') if type(psbt) is dict else None
        require(type(decoded) is dict,'PSBT_VERSION','decodepsbt has no unsigned transaction')
        expected=[];match=[];input_total=0
        for i in decoded['vin']:
            prev=self.rpc('gettxout',i['txid'],i['vout'],True)
            require(prev and prev['confirmations']>=self.confirmations,'INPUT_UNCONFIRMED','Funding input is unconfirmed or spent')
            require(not prev.get('coinbase') or prev['confirmations']>=100,'COINBASE_IMMATURE','Immature input')
            input_total+=to_atoms(prev['value'])
        for i,o in enumerate(decoded['vout']):
            spk=o['scriptPubKey'];value=to_atoms(o['value'])
            if spk['hex']==terms.lock_commitment and value==atoms(terms.amount_atoms):role='htlc';match.append(i)
            else:
                require(self._owned(spk['hex'],spk.get('address')),'CHANGE_AUTHORITY','Non-wallet output in funding transaction')
                role='change'
            expected.append((spk['hex'],str(value),role))
        require(len(match)==1,'FUNDING_OUTPUT','Expected exactly one exact HTLC output')
        require(input_total-sum(int(o[1]) for o in expected)==fee,'FEE_MISMATCH','Wallet fee does not match chain inputs')
        plan=FundingPlan(self.network,sid,reservation_id,self.asset.id,
                         tuple(f"{v['txid']}:{v['vout']}" for v in decoded['vin']),str(input_total),tuple(expected),max_fee_atoms)
        self.journal.store.lock_coins(reservation_id,self.asset.id,list(plan.inputs))
        owned={o[0] for o in expected if o[2]=='change'}
        raw=self.adapter.sign_funding(result['psbt'],approved_plan=plan,is_owned_change=lambda x:x in owned)
        tx=self.rpc('decoderawtransaction',raw)
        require(tx['txid']==decoded['txid'],'FUNDING_MALLEATED','Witness signing changed the funding txid')
        ref={'txid':tx['txid'],'vout':match[0]}
        return Prepared(tx['txid'],raw,ref,str(fee),{'plan_id':plan.id,'inputs':list(plan.inputs)})
    def _dest_script(self,address):
        valid=self.rpc('validateaddress',address)
        require(valid.get('isvalid') is True,'PAYOUT','Invalid payout')
        return valid['scriptPubKey']
    def _single_psbt(self,terms,ref,destination,fee,locktime=0):
        require(0<fee<atoms(terms.amount_atoms),'FEE_CAP','Fee consumes contract')
        psbt=self.rpc('createpsbt',[{'txid':ref['txid'],'vout':ref['vout'],'sequence':0xfffffffd}],
                      [{destination:coin_string(atoms(terms.amount_atoms)-fee)}],locktime,True)
        return add_witness_utxo(psbt,atoms(terms.amount_atoms),terms.lock_commitment)
    def initial_spend_fee(self,cap):
        # PQ witnesses are materially larger than ECDSA. This conservative size
        # estimate is local policy, not a consensus rule; all final fees stay capped.
        target=self.fee_rate*(4500 if self.family=='btx' else 220)
        value=min(atoms(cap),target)
        require(value>0,'FEE_CAP','A positive fee cap is required')
        return value
    def prepare_refund(self,sid,terms,ref,key,fee_atoms=None):
        c=self.watch_terms(terms,key);fee=atoms(fee_atoms) if fee_atoms is not None else self.initial_spend_fee(terms.max_refund_fee_atoms)
        require(fee<=atoms(terms.max_refund_fee_atoms),'FEE_CAP','Refund exceeds agreement fee')
        if self.family=='btx':
            psbt=self._single_psbt(terms,ref,terms.refund_payout,fee,terms.lock_value)
            signed=self.wallet('walletprocesspsbt',psbt,{'p2mr_leaf':{f"{ref['txid']}:{ref['vout']}":1},'finalize':True})
            final=self.rpc('finalizepsbt',signed['psbt'],True)
            require(final.get('complete') is True,'REFUND_UNSIGNED','Native refund could not be presigned')
            raw=final['hex']
        else:
            priv=self.vault.key(key['handle'],family='btc',genesis=self.asset.genesis,role='refund')
            tx=build_spend(ref['txid'],ref['vout'],atoms(terms.amount_atoms),fee,bytes.fromhex(self._dest_script(terms.refund_payout)),
                           bytes.fromhex(c['script']),priv,refund_height=terms.lock_value,expected_pubkey=bytes.fromhex(terms.refund_key))
            raw=tx.encode().hex()
        dec=self.rpc('decoderawtransaction',raw)
        self._check_spend(dec,terms,ref,terms.refund_payout,fee,refund=True)
        return Prepared(dec['txid'],raw,ref,str(fee),{})
    def prepare_claim_template(self,sid,terms,ref,key,fee_atoms=None,*,replacing=False):
        c=self.watch_terms(terms,key);fee=atoms(fee_atoms) if fee_atoms is not None else self.initial_spend_fee(terms.max_claim_fee_atoms)
        require(fee<=atoms(terms.max_claim_fee_atoms),'FEE_CAP','Claim exceeds signed fee cap')
        require(fee>0,'FEE_CAP','A positive UTXO claim fee is required')
        report=self.observe(terms,ref)
        # A replacement is built while our own claim is still unconfirmed, so
        # the spend's confirmation count is not the funding depth.
        if replacing:
            require(report.observation.present and report.observation.exact_terms and not report.observation.refunded and not report.observation.conflicting,
                    'FUNDING_UNVERIFIED','Claim funding is not available to replace')
        else:
            require(report.observation.settled(self.family,self._policy(),self.now()) and not report.observation.refunded,
                    'FUNDING_UNVERIFIED','Claim funding is not sufficiently confirmed')
        if self.family=='btx':
            psbt=self._single_psbt(terms,ref,terms.payout,fee)
            signed=self.wallet('walletprocesspsbt',psbt,{'htlc_presign':True,'p2mr_leaf':{f"{ref['txid']}:{ref['vout']}":0},
                                                     'min_confirmations':self.confirmations,'finalize':False})
            require(not signed.get('complete'),'CLAIM_TEMPLATE','Unexpected finalized claim without secret')
            return {'family':'btx','psbt':signed['psbt'],'fee_atoms':str(fee)}
        priv=self.vault.key(key['handle'],family='btc',genesis=self.asset.genesis,role='claim')
        script=bytes.fromhex(c['script']);tx=Transaction([TxInput(ref['txid'],ref['vout'])],
              [TxOutput(atoms(terms.amount_atoms)-fee,bytes.fromhex(self._dest_script(terms.payout)))])
        signature=sign_digest(priv,tx.sighash_all(0,script,atoms(terms.amount_atoms)))+b'\x01'
        return {'family':'btc','unsigned':tx.encode().hex(),'signature':signature.hex(),'script':script.hex(),'fee_atoms':str(fee)}
    def finish_claim(self,terms,ref,template,secret):
        require(hashlock(secret)==terms.hashlock,'PREIMAGE','Wrong contract secret')
        fee=atoms(template['fee_atoms']);require(fee<=atoms(terms.max_claim_fee_atoms),'FEE_CAP','Claim fee exceeds agreement')
        if self.family=='btx':
            final=self.rpc('finalizepsbt',template['psbt'],True,[secret.hex()])
            require(final.get('complete') is True,'CLAIM_UNSIGNED','Presigned BTX claim did not finalize')
            raw=final['hex']
        else:
            tx=Transaction.decode(bytes.fromhex(template['unsigned']))
            tx.inputs[0].witness=[bytes.fromhex(template['signature']),secret,b'\x01',bytes.fromhex(template['script'])]
            raw=tx.encode().hex()
        dec=self.rpc('decoderawtransaction',raw);self._check_spend(dec,terms,ref,terms.payout,fee)
        return Prepared(dec['txid'],raw,ref,str(fee),{})
    def _check_spend(self,tx,terms,ref,payout,fee,refund=False):
        require(len(tx['vin'])==1 and len(tx['vout'])==1,'SPEND_SHAPE','Unexpected spending transaction shape')
        i=tx['vin'][0];o=tx['vout'][0]
        require(i['txid']==ref['txid'] and i['vout']==ref['vout'],'SIGNER_SCOPE','Wrong contract input')
        if not refund:require(i.get('sequence',0xffffffff)<=0xfffffffd,'NOT_REPLACEABLE','Claim must signal replacement')
        require(o['scriptPubKey']['hex']==self._dest_script(payout) and to_atoms(o['value'])==atoms(terms.amount_atoms)-fee,
                'SIGNER_SCOPE','Spend payout or amount changed')
        if refund:require(tx['locktime']==terms.lock_value and i['sequence']<0xffffffff,'REFUND_LOCK','Incorrect refund locktime')
    def _policy(self):
        from .policy import SafetyPolicy
        return SafetyPolicy(btx_confirmations=self.confirmations if self.family=='btx' else 20,
                            btc_confirmations=self.confirmations if self.family=='btc' else 6)
    def _read_tx(self,txid):
        for fn in (self.wallet,self.watch):
            try:
                w=fn('gettransaction',txid,True)
                d=self.rpc('decoderawtransaction',w['hex'])
                return {**d,**{k:w[k] for k in ('blockhash','confirmations') if k in w}}
            except SwapError:pass
        return self.rpc('getrawtransaction',txid,True)
    def has_transaction(self,txid):
        try:return self._read_tx(txid).get('txid')==txid
        except SwapError:return False
    def broadcast(self,raw):
        # sendrawtransaction has its own fee-rate sanity check. Never bypass it.
        return self.rpc('sendrawtransaction',raw)
    def _spending(self,ref,terms,funding_height):
        key='spend:'+self.asset.id+':'+ref['txid']+':'+str(ref['vout'])
        cached=self.journal.setting(key,{})
        if cached.get('txid'):
            try:
                tx=self._read_tx(cached['txid'])
                if tx.get('blockhash'):
                    h=self.rpc('getblockheader',tx['blockhash'])
                    if h.get('confirmations',0)>0:return tx
                elif self.rpc('getmempoolentry',cached['txid']):return tx
            except SwapError:pass
            cached={}
        try:
            rows=self.rpc('gettxspendingprevout',[{'txid':ref['txid'],'vout':ref['vout']}])
            if rows and rows[0].get('spendingtxid'):
                tx=self.rpc('getrawtransaction',rows[0]['spendingtxid'],True)
                self.journal.set_setting(key,{'txid':tx['txid']});return tx
        except SwapError:pass
        tip=self.rpc('getblockcount')
        start=max(0,funding_height,cached.get('height',funding_height)-20)
        stop=min(tip,start+63)
        for height in range(start,stop+1):
            blockhash=self.rpc('getblockhash',height);block=self.rpc('getblock',blockhash,2)
            for tx in block['tx']:
                if any(i.get('txid')==ref['txid'] and i.get('vout')==ref['vout'] for i in tx['vin']):
                    tx={**tx,'blockhash':blockhash,'confirmations':tip-height+1}
                    self.journal.set_setting(key,{'txid':tx['txid'],'height':height});return tx
        self.journal.set_setting(key,{'height':stop+1})
        return None
    def observe(self,terms,ref):
        clock=self.clock();now=self.now()
        if ref is None:return Report(LegObservation(observed_at=now),clock)
        hex32(ref['txid']);integer(ref['vout'],hi=0xffffffff);self.verify_terms(terms)
        try:funding=self._read_tx(ref['txid'])
        except SwapError:return Report(LegObservation(observed_at=now),clock)
        if ref['vout']>=len(funding['vout']):return Report(LegObservation(conflicting=True,observed_at=now),clock)
        output=funding['vout'][ref['vout']]
        exact=output['scriptPubKey']['hex']==terms.lock_commitment and to_atoms(output['value'])==atoms(terms.amount_atoms)
        conf=0;canonical=True;fund_height=max(0,clock.height-144);blockhash=funding.get('blockhash','')
        if blockhash:
            header=self.rpc('getblockheader',blockhash);conf=max(0,header.get('confirmations',0));canonical=conf>0
            fund_height=header.get('height',fund_height)
        if funding.get('confirmations',0)<0:canonical=False
        coin=self.rpc('gettxout',ref['txid'],ref['vout'],True)
        if coin:
            exact=exact and coin['scriptPubKey']['hex']==terms.lock_commitment and to_atoms(coin['value'])==atoms(terms.amount_atoms)
            canonical=coin.get('bestblock')==self.rpc('getbestblockhash')
            conf=coin.get('confirmations',0)
            if coin.get('coinbase') and conf<100:exact=False
            return Report(LegObservation(True,exact,canonical,conf,False,False,False,not exact,now),clock,None,blockhash)
        spending=self._spending(ref,terms,fund_height)
        if not spending:return Report(LegObservation(True,exact,canonical,conf,False,False,False,not exact,now),clock,None,blockhash)
        preimage=None
        for i in spending['vin']:
            if (i.get('txid'),i.get('vout'))==(ref['txid'],ref['vout']):
                for value in i.get('txinwitness',[]):
                    if len(value)==64:
                        try:raw=bytes.fromhex(value)
                        except ValueError:continue
                        if hashlib.sha256(raw).hexdigest()==terms.hashlock:preimage=value
        sconf=0;scanonical=True;sblock=spending.get('blockhash','')
        if sblock:
            h=self.rpc('getblockheader',sblock);sconf=max(0,h.get('confirmations',0));scanonical=sconf>0
        claimed=preimage is not None
        refunded=not claimed and spending.get('locktime',0)>=terms.lock_value
        return Report(LegObservation(True,exact,canonical and scanonical,sconf,False,claimed,refunded,
                                     not exact or not(claimed or refunded),now),clock,preimage,sblock)
    def relock(self):
        with self.journal.store.lock:
            rows=self.journal.store.db.execute('SELECT outpoint FROM coinlocks WHERE chain=?',(self.asset.id,)).fetchall()
        if rows:
            out=[{'txid':v.rsplit(':',1)[0],'vout':int(v.rsplit(':',1)[1])} for (v,) in rows]
            self.wallet('lockunspent',False,out)
