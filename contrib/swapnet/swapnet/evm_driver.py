"""Native-ETH execution with nonce-safe recovery intents and finalized-state checks.

An EVM refund is NOT presigned with a speculative future nonce. Its immutable
contract call, beneficiary, signer handle, and gas cap are journaled before
funding; an actual nonce is reserved only when the refund is executable. ETH is
credited by the contract and then withdrawn to the agreed local beneficiary.
"""
from dataclasses import asdict
import time
from .assets import Asset
from .canonical import atoms,digest,hashlock,hex32
from .errors import require,SwapError
from .policy import ChainClock
from .machine import LegObservation
from .drivers import Prepared,Report
from .evm import EVMAdapter,Eip1559Transaction,address_bytes,address_from_key,calldata,keccak256,lock_id

ZERO='0x'+'00'*20

class EVMDriver:
    family='evm'
    def __init__(self,asset,rpc,journal,vault,contract,runtime_hash,*,clock=None):
        self.asset=Asset.parse(asset);require(self.asset.family=='evm' and self.asset.token=='native','ASSET_DISABLED','Automatic EVM execution is native ETH only')
        self.rpc,self.journal,self.vault=rpc,journal,vault
        self.now=clock or (lambda:int(time.time()))
        self.adapter=EVMAdapter(rpc,self.asset.genesis,self.asset.chain_id,contract,runtime_hash)
        self.contract,self.runtime_hash=contract,runtime_hash
    def _account(self):
        setting='evm-account:'+self.asset.id;kid=self.journal.setting(setting)
        if not kid:
            kid=self.vault.create_key('evm',self.asset.genesis,'funding');self.journal.set_setting(setting,kid)
        key=self.vault.key(kid,family='evm',genesis=self.asset.genesis,role='funding')
        return kid,key,address_from_key(key)
    def ready(self):self.adapter.check_chain();self._account();return True
    def inventory(self):
        # Quotes reserve against the local latest balance. A freshly funded
        # account is still 0 at finalized, which is not the same as a reservation.
        # Settlement still requires the configured finality tag.
        self.adapter.check_chain();return int(self.rpc('eth_getBalance',self._account()[2],'latest'),16)
    def new_key(self,role):
        require(role in {'claim','refund'},'KEY_ROLE','Invalid role')
        kid,key,address=self._account()
        return {'public':address,'handle':kid,'payout':address,'role':'funding'}
    def clock(self):
        self.adapter.check_chain();b=self.rpc('eth_getBlockByNumber','latest',False)
        require(b and b.get('hash'),'CHAIN_SYNC','EVM chain tip unavailable')
        now=self.now();timestamp=int(b['timestamp'],16)
        return ChainClock('evm',int(b['number'],16),timestamp,now,1,24,now-timestamp>7200)
    def commitment(self,h,claim,refund,deadline):
        address_bytes(claim);address_bytes(refund);hex32(h)
        return digest('BTX/SWAPNET/EVM-CONTRACT/2',{'asset':self.asset.id,'contract':self.contract,'runtime_hash':self.runtime_hash,
                      'hashlock':h,'claim_to':claim,'refund_to':refund,'refund_at':deadline})
    def verify_terms(self,t):
        require(t.asset==self.asset.id and t.lock_domain=='timestamp','CHAIN','EVM terms use wrong chain or lock domain')
        require(t.lock_commitment==self.commitment(t.hashlock,t.claim_key,t.refund_key,t.lock_value),'CONTRACT_TERMS','EVM commitment changed')
        require(t.claim_key==t.payout and t.refund_key==t.refund_payout,'PAYOUT','Initial ETH profile pays directly to the approved account')
        require(t.claim_key!=t.refund_key,'SELF_SWAP','Same account cannot fund and claim')
        return {'contract':self.contract,'script_pubkey':t.lock_commitment}
    def watch_terms(self,t,local_key=None):
        self.adapter.check_chain();self.verify_terms(t)
        if local_key:require(local_key['public'] in (t.claim_key,t.refund_key) and local_key['public']==self._account()[2],
                             'SIGNER_SCOPE','EVM key handle is not the local account')
        return {'contract':self.contract}
    def _fees(self,gas_cap):
        latest=self.rpc('eth_getBlockByNumber','latest',False)
        require('baseFeePerGas' in latest,'EVM_FEE_MARKET','EIP-1559 base fee unavailable')
        base=int(latest['baseFeePerGas'],16)
        priority=int(self.rpc('eth_maxPriorityFeePerGas'),16)
        return priority,max(priority,base*2+priority)
    def _prepare(self,sid,kind,key_handle,to,value,data,cap,*,fixed_nonce=None,replacement_of=None):
        self.adapter.check_chain();cap=atoms(cap,positive=True)
        key=self.vault.key(key_handle,family='evm',genesis=self.asset.genesis,role='funding');sender=address_from_key(key)
        require(sender==self._account()[2],'SIGNER_SCOPE','Unexpected ETH signing account')
        req={'from':sender,'to':to,'value':hex(value),'data':'0x'+data.hex()}
        estimated=int(self.rpc('eth_estimateGas',req),16);gas=max(21000,(estimated*12+9)//10)
        priority,maximum=self._fees(cap)
        require(gas*maximum<=cap,'FEE_CAP','Estimated EVM transaction exceeds approved gas cap')
        pending=int(self.rpc('eth_getTransactionCount',sender,'pending'),16)
        operation=digest('BTX/SWAPNET/EVM-NONCE/2',{'swap_id':sid,'kind':kind,'data_hash':keccak256(data).hex()})
        nonce=(self.journal.reserve_nonce(self.asset.id,sender,operation,pending) if fixed_nonce is None else fixed_nonce)
        balance=int(self.rpc('eth_getBalance',sender,'pending'),16)
        require(balance>=value+gas*maximum,'INSUFFICIENT_GAS','Local ETH account cannot fund value plus approved gas')
        tx=Eip1559Transaction(self.asset.chain_id,nonce,priority,maximum,gas,address_bytes(to),value,data)
        raw=tx.sign(key,sender);txid=tx.validate_signed(raw,sender)
        metadata={'nonce':nonce,'gas':gas,'max_fee_per_gas':str(maximum),'priority_fee_per_gas':str(priority),'sender':sender,
                  'to':to,'value':str(value),'data':data.hex(),'key_handle':key_handle}
        if replacement_of:metadata['replacement_of']=replacement_of
        return Prepared(txid,'0x'+raw.hex(),{},str(gas*maximum),metadata)
    def reference(self,sid,t,txid):
        salt=digest('BTX/SWAPNET/EVM-SALT/2',{'swap_id':sid,'asset':self.asset.id})
        return {'txid':txid,'lock_id':lock_id(self.asset.chain_id,self.contract,t.refund_key,salt),'salt':salt}
    def verify_reference(self,sid,t,ref):
        require(ref==self.reference(sid,t,ref['txid']),'CONTRACT_ID','Counterparty changed sender-scoped contract identifier')
    def prepare_funding(self,sid,t,key,reservation_id,max_fee_atoms):
        self.watch_terms(t,key)
        require(key['public']==t.refund_key,'SIGNER_SCOPE','Wrong ETH funder')
        ref=self.reference(sid,t,'0x'+'00'*32)
        data=self.adapter.funding_data(ref['salt'],t.hashlock,t.claim_key,t.lock_value)
        # Reserve enough owner-approved fee capacity for refund plus withdrawal.
        cap=atoms(max_fee_atoms)-atoms(t.max_refund_fee_atoms)
        require(cap>0,'FEE_CAP','No EVM funding gas allowance after recovery reserve')
        prepared=self._prepare(sid,'fund',key['handle'],self.contract,atoms(t.amount_atoms),data,str(cap))
        return Prepared(prepared.txid,prepared.raw,self.reference(sid,t,prepared.txid),prepared.fee_atoms,prepared.metadata)
    def refund_plan(self,sid,t,ref,key,cap):
        self.watch_terms(t,key);self.verify_reference(sid,t,ref)
        require(atoms(cap)>=atoms(t.max_refund_fee_atoms)>0,'FEE_CAP','Insufficient EVM recovery reserve')
        return {'swap_id':sid,'asset':self.asset.id,'key_handle':key['handle'],'lock_id':ref['lock_id'],
                'beneficiary':t.refund_payout,'refund_at':t.lock_value,'fee_cap_atoms':t.max_refund_fee_atoms}
    def materialize_refund(self,plan):
        require(plan['asset']==self.asset.id and plan['beneficiary']==self._account()[2],'SIGNER_SCOPE','Recovery intent changed')
        require(self.clock().timestamp>=plan['refund_at'],'REFUND_EARLY','EVM refund deadline not reached')
        cap=atoms(plan['fee_cap_atoms'])//2
        return self._prepare(plan['swap_id'],'refund',plan['key_handle'],self.contract,0,
                             calldata('refund(bytes32)',bytes.fromhex(plan['lock_id'])),str(cap))
    def prepare_claim_template(self,sid,t,ref,key):
        self.watch_terms(t,key);self.verify_reference(sid,t,ref)
        require(key['public']==t.claim_key,'SIGNER_SCOPE','Wrong ETH claimant')
        report=self.observe(t,ref)
        require(report.observation.present and report.observation.exact_terms and report.observation.canonical and report.observation.finalized,
                'FUNDING_UNVERIFIED','ETH funding has not finalized')
        return {'family':'evm','swap_id':sid,'lock_id':ref['lock_id'],'key_handle':key['handle'],
                'beneficiary':t.payout,'fee_atoms':t.max_claim_fee_atoms}
    def finish_claim(self,t,ref,template,secret):
        require(hashlock(secret)==t.hashlock,'PREIMAGE','Incorrect EVM preimage')
        require(template['beneficiary']==t.payout==self._account()[2],'SIGNER_SCOPE','ETH claim beneficiary changed')
        require(template['lock_id']==ref['lock_id'],'CONTRACT_ID','Claim contract changed')
        cap=atoms(t.max_claim_fee_atoms)//2
        return self._prepare(template['swap_id'],'claim',template['key_handle'],self.contract,0,
                             calldata('claim(bytes32,bytes32)',bytes.fromhex(ref['lock_id']),secret),str(cap))
    def ensure_withdrawal(self,sid,t,key,*,refund=False):
        """Return True only after the agreed ETH payout is finalized and withdrawable."""
        beneficiary=t.refund_payout if refund else t.payout
        require(key['public']==beneficiary==self._account()[2],'SIGNER_SCOPE','Wrong withdrawal beneficiary')
        cap=atoms(t.max_refund_fee_atoms if refund else t.max_claim_fee_atoms)//2
        tag=self.rpc('eth_getBlockByNumber','finalized',False)
        credit=int(self.rpc('eth_call',{'to':self.contract,'data':'0x'+calldata('credits(address,address)',
                       address_bytes(beneficiary),address_bytes(ZERO)).hex()},tag['number']),16)
        ops=[o for o in self.journal.operations(sid,private=True) if o['asset']==self.asset.id and o['kind']=='withdraw']
        if ops:
            op=ops[-1]
            if not self.has_transaction(op['txid']):self.journal.broadcast(op['id'],self)
            receipt=self.rpc('eth_getTransactionReceipt',op['txid'])
            if not receipt:return False
            require(int(receipt['status'],16)==1,'WITHDRAW_REVERTED','ETH withdrawal transaction reverted')
            return int(receipt['blockNumber'],16)<=int(tag['number'],16) and self.rpc('eth_getBlockByNumber',receipt['blockNumber'],False)['hash']==receipt['blockHash']
        require(credit>=atoms(t.amount_atoms),'CREDIT_MISSING','Finalized ETH credit is insufficient')
        p=self._prepare(sid,'withdraw',key['handle'],self.contract,0,
                        calldata('withdrawAmount(address,address,uint256)',address_bytes(ZERO),address_bytes(beneficiary),atoms(t.amount_atoms)),str(cap))
        oid=self.journal.prepare(sid,self.asset.id,'withdraw',p.txid,p.raw,{**p.metadata,'fee_atoms':p.fee_atoms})
        self.journal.broadcast(oid,self);return False
    def replace(self,old,new_cap):
        self.adapter.check_chain();m=old['metadata'];cap=atoms(new_cap,positive=True)
        require(m['to']==self.contract and m['value']=='0','REPLACEMENT_SCOPE','Only contract recovery calls may be replaced')
        key=self.vault.key(m['key_handle'],family='evm',genesis=self.asset.genesis,role='funding')
        priority,maximum=self._fees(cap)
        priority=max(priority,(int(m['priority_fee_per_gas'])*113+99)//100)
        maximum=max(maximum,(int(m['max_fee_per_gas'])*113+99)//100,priority)
        require(m['gas']*maximum<=cap,'FEE_CAP','Replacement gas prices exceed the absolute fee cap')
        tx=Eip1559Transaction(self.asset.chain_id,m['nonce'],priority,maximum,m['gas'],address_bytes(m['to']),0,bytes.fromhex(m['data']))
        raw=tx.sign(key,m['sender']);txid=tx.validate_signed(raw,m['sender'])
        metadata={**m,'max_fee_per_gas':str(maximum),'priority_fee_per_gas':str(priority),'replacement_of':old['txid']}
        return Prepared(txid,'0x'+raw.hex(),m.get('reference',{}),str(m['gas']*maximum),metadata)
    def has_transaction(self,txid):
        tx=self.rpc('eth_getTransactionByHash',txid)
        return bool(tx and tx.get('hash')==txid)
    def broadcast(self,raw):return self.adapter.broadcast(bytes.fromhex(raw.removeprefix('0x')))
    def observe(self,t,ref):
        clock=self.clock();now=self.now();self.verify_terms(t)
        if ref is None:return Report(LegObservation(observed_at=now),clock)
        expected={'hashlock':t.hashlock,'token':ZERO,'refund_to':t.refund_key,'claim_to':t.claim_key,
                  'amount':atoms(t.amount_atoms),'refund_at':t.lock_value}
        obs=self.adapter.observe(ref['lock_id'],expected,now)
        # The peer-supplied txid is not proof of this lock. A successful but
        # unrelated transaction must not count, and a reverted one must not
        # abort observation of the other leg.
        receipt=self._funding_receipt(ref)
        preimage=None;blockhash=''
        if receipt:
            blockhash=receipt['blockHash']
            canonical=self.rpc('eth_getBlockByNumber',receipt['blockNumber'],False)['hash']==blockhash
            if not canonical:obs=LegObservation(observed_at=now)
            else:
                # A mined but not finalized reveal is already public. Preserve it even
                # while finalized storage still reports Locked.
                logs=self.rpc('eth_getLogs',{'address':self.contract,'fromBlock':receipt['blockNumber'],'toBlock':'latest',
                                'topics':['0x'+keccak256(b'Claimed(bytes32,bytes32)').hex(),'0x'+ref['lock_id']]})
                require(type(logs) is list and len(logs)<=64,'LOG_LIMIT','Excessive claim logs')
                for log in logs:
                    raw=bytes.fromhex(log['data'].removeprefix('0x'))
                    if len(raw)==32 and hashlock(raw)==t.hashlock:preimage=raw.hex()
        return Report(obs,clock,preimage,blockhash)
    def _funding_receipt(self,ref):
        receipt=self.rpc('eth_getTransactionReceipt',ref['txid'])
        if not receipt or not receipt.get('blockNumber') or int(receipt.get('status','0x0'),16)!=1:return None
        locked='0x'+keccak256(b'Locked(bytes32,bytes32,address,address,address,uint256,uint64)').hex()
        want='0x'+ref['lock_id']
        for log in receipt.get('logs') or []:
            topics=log.get('topics') or []
            if str(log.get('address','')).lower()==self.contract.lower() and topics and topics[0]==locked and len(topics)>1 and topics[1]==want:
                return receipt
        return None
    def relock(self):
        # No UTXOs; nonces are durably reserved in sn_nonces and never guessed.
        self.adapter.check_chain()
