"""BTX P2MR and Bitcoin client adapters, with chain identity and exact-lock checks.

These adapters are not network-facing signers. The caller supplies scoped, local
RPC authorities. No private BTX key, WIF, xpub, pqhd seed, or mnemonic is converted.
"""
from dataclasses import dataclass
from decimal import Decimal
import re
from .canonical import hex32,integer,hashlock
from .errors import require
from .bitcoin import htlc_script,p2wsh,p2wsh_address,Transaction
from .machine import LegObservation

COIN=100_000_000

def to_atoms(value):
    require(type(value) in {str,int,Decimal},'RPC_AMOUNT','RPC amount must not pass through binary floating point')
    n=Decimal(value)*COIN
    require(n==n.to_integral_value() and n>=0,'RPC_AMOUNT','Non-integral coin amount')
    return int(n)

def coin_string(n):
    require(type(n) is int and n>=0,'AMOUNT','Invalid amount')
    return str(n//COIN)+'.'+str(n%COIN).zfill(8)

@dataclass(frozen=True)
class UtxoLock:
    txid:str
    vout:int
    atoms:int
    script_pubkey:str
    def __post_init__(self):
        hex32(self.txid);integer(self.vout,hi=0xffffffff)
        require(type(self.atoms) is int and self.atoms>0,'AMOUNT','Invalid lock value')
        require(type(self.script_pubkey) is str and re.fullmatch(r'[0-9a-f]+',self.script_pubkey) and len(self.script_pubkey)%2==0,'SCRIPT','Invalid script hex')

class UtxoAdapter:
    def __init__(self,rpc,wallet_rpc,genesis,family):
        self.rpc,self.wallet,self.genesis,self.family=rpc,wallet_rpc,hex32(genesis),family
        require(family in {'btc','btx'},'CHAIN','Unsupported UTXO chain')
    def check_chain(self):
        require(self.rpc('getblockhash',0)==self.genesis,'GENESIS_MISMATCH','Wrong local chain')
        info=self.rpc('getblockchaininfo')
        require(info.get('initialblockdownload') is False,'CHAIN_SYNC','Client is not synchronized')
        return info
    def observe(self,lock:UtxoLock,now):
        self.check_chain()
        txout=self.rpc('gettxout',lock.txid,lock.vout,True)
        if txout is None:return LegObservation(observed_at=now)
        exact=(to_atoms(txout['value'])==lock.atoms and txout['scriptPubKey']['hex']==lock.script_pubkey)
        # bestblock anchors this UTXO view; read it again to avoid mixing chain tips.
        canonical=(txout.get('bestblock')==self.rpc('getbestblockhash'))
        confirmations=txout.get('confirmations',0)
        if txout.get('coinbase') and confirmations<100:exact=False
        return LegObservation(True,exact,canonical,confirmations,False,False,False,False,now)
    def prepare_funding(self,address,amount_atoms,fee_rate,max_fee_atoms,minconf):
        self.check_chain()
        integer(minconf,lo=1);integer(fee_rate,lo=1,hi=10000)
        options={'lockUnspents':False,'replaceable':False,'include_unsafe':False,'fee_rate':fee_rate,'minconf':minconf}
        result=self.wallet('walletcreatefundedpsbt',[],[{address:coin_string(amount_atoms)}],0,options,True)
        require(to_atoms(result['fee'])<=max_fee_atoms,'FEE_CAP','Funding fee exceeds approved cap')
        return result
    def sign_funding(self,psbt,*,approved_plan,is_owned_change):
        decoded=self.rpc('decodepsbt',psbt)
        approved_plan.verify_decoded(decoded['tx'],is_owned_change=is_owned_change,atoms_from_rpc=to_atoms)
        signed=self.wallet('walletprocesspsbt',psbt,True,'ALL',True)
        require(signed.get('complete') is True,'SIGNING_INCOMPLETE','Wallet did not sign all inputs')
        finalized=self.rpc('finalizepsbt',signed['psbt'],True)
        require(finalized.get('complete') is True,'SIGNING_INCOMPLETE','PSBT could not be finalized')
        approved_plan.verify_decoded(self.rpc('decoderawtransaction',finalized['hex']),
                                     is_owned_change=is_owned_change,atoms_from_rpc=to_atoms)
        return finalized['hex']
    def broadcast(self,raw):return self.rpc('sendrawtransaction',raw)

class BTXAdapter(UtxoAdapter):
    def __init__(self,rpc,wallet_rpc,genesis):super().__init__(rpc,wallet_rpc,genesis,'btx')
    def descriptor(self,hash_hex,claim_pubkey,refund_pubkey,refund_height):
        hex32(hash_hex);integer(refund_height,lo=1,hi=499999999)
        # Initial profile is raw ML-DSA-44 public keys; other PQ schemes need an explicit profile.
        for key in (claim_pubkey,refund_pubkey):
            require(type(key) is str and re.fullmatch(r'[0-9a-f]{2624}',key),'BTX_PQ_KEY','Expected ML-DSA-44 public key, not secp256k1 or a seed')
        require(claim_pubkey!=refund_pubkey,'KEY_REUSE','Claim/refund keys must differ')
        raw=f'mr(htlc_sha256({hash_hex},{claim_pubkey}),refund({refund_height},{refund_pubkey}))'
        info=self.rpc('getdescriptorinfo',raw)
        descriptor=raw+'#'+info['checksum']
        address=self.rpc('deriveaddresses',descriptor)[0]
        valid=self.rpc('validateaddress',address)
        require(valid.get('isvalid') is True and 'scriptPubKey' in valid,'BTX_DESCRIPTOR','Node did not validate funding script')
        return {'descriptor':descriptor,'address':address,'script_pubkey':valid['scriptPubKey']}
    def watch(self,descriptor):
        result=self.wallet('importdescriptors',[{'desc':descriptor,'timestamp':'now','internal':False}])
        require(len(result)==1 and result[0].get('success') is True,'WATCH_FAILED','Wallet could not import HTLC')
    def claim(self,descriptor,lock,secret,destination,fee,now,minconf=20):
        obs=self.observe(lock,now)
        require(obs.present and obs.exact_terms and obs.canonical and obs.confirmations>=minconf,'FUNDING_UNVERIFIED','BTX funding not sufficiently confirmed')
        hashlock(secret)
        result=self.wallet('buildhtlcclaim',descriptor,{'txid':lock.txid,'vout':lock.vout},secret.hex(),destination,fee)
        require(result.get('complete') is True,'SIGNING_INCOMPLETE','BTX HTLC claim not complete')
        return result['hex']
    def refund(self,descriptor,lock,destination,height,fee):
        integer(height,lo=1,hi=499999999)
        require(self.rpc('getblockcount')>=height,'REFUND_EARLY','BTX refund lock has not matured')
        result=self.wallet('buildhtlcrefund',descriptor,{'txid':lock.txid,'vout':lock.vout},destination,height,fee)
        require(result.get('complete') is True,'SIGNING_INCOMPLETE','BTX HTLC refund not complete')
        return result['hex']
    def verify_message(self,address,signature,message):return self.rpc('verifymessage',address,signature,message)

class BitcoinAdapter(UtxoAdapter):
    def __init__(self,rpc,wallet_rpc,genesis,hrp):
        super().__init__(rpc,wallet_rpc,genesis,'btc');self.hrp=hrp
    def contract(self,hash_hex,claim_pubkey,refund_pubkey,refund_height):
        script=htlc_script(hash_hex,claim_pubkey,refund_pubkey,refund_height)
        return {'script':script.hex(),'script_pubkey':p2wsh(script).hex(),'address':p2wsh_address(script,self.hrp)}
    def txid(self,raw):return Transaction.decode(bytes.fromhex(raw)).txid
