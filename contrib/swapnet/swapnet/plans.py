"""Strict signer-side transaction plans. Network code cannot invent an approval."""
from dataclasses import dataclass,asdict
from .canonical import atoms,hex32,digest,integer
from .errors import require
from .assets import Asset

@dataclass(frozen=True)
class FundingPlan:
    network:str
    swap_id:str
    reservation_id:str
    asset:str
    inputs:tuple
    input_atoms:str
    outputs:tuple
    max_fee_atoms:str
    def __post_init__(self):
        Asset.parse(self.asset)
        for v in (self.network,self.swap_id,self.reservation_id):hex32(v)
        require(0<len(self.inputs)<=256 and len(set(self.inputs))==len(self.inputs),'INPUTS','Invalid or duplicate inputs')
        require(0<len(self.outputs)<=16,'OUTPUTS','Output count invalid')
        total=0
        for script,value,role in self.outputs:
            require(type(script) is str and len(script)%2==0 and len(script)>0,'SCRIPT','Invalid script')
            try:bytes.fromhex(script)
            except ValueError:require(False,'SCRIPT','Invalid script hex')
            total+=atoms(value,positive=True)
            require(role in {'htlc','change'},'OUTPUT_ROLE','Unexpected payout role')
        require(sum(1 for o in self.outputs if o[2]=='htlc')==1,'OUTPUT_ROLE','Exactly one funded HTLC required')
        fee=atoms(self.input_atoms)-total
        require(0<=fee<=atoms(self.max_fee_atoms),'FEE_CAP','Funding fee outside cap')
    @property
    def id(self):return digest('BTX/SWAPNET/FUNDING-PLAN/1',{**asdict(self),'inputs':list(self.inputs),'outputs':[list(o) for o in self.outputs]})
    def verify_decoded(self,tx,*,is_owned_change,atoms_from_rpc):
        require(type(tx) is dict and tx.get('locktime')==0,'FUNDING_PLAN','Unexpected funding locktime')
        ins=tuple(f"{x['txid']}:{x['vout']}" for x in tx['vin'])
        require(ins==self.inputs,'PLAN_MUTATED','Input order or outpoints changed')
        require(len(tx['vout'])==len(self.outputs),'PLAN_MUTATED','Output count changed')
        for output,(script,value,role) in zip(tx['vout'],self.outputs):
            require(output['scriptPubKey']['hex']==script and atoms_from_rpc(output['value'])==atoms(value),
                    'PLAN_MUTATED','Output amount or script changed')
            if role=='change':require(is_owned_change(script) is True,'CHANGE_AUTHORITY','Change is not signer-owned')
        # Funding is deliberately non-RBF in this profile. Refunds/claims have
        # their own fee-bump policy; do not conflate the three transaction kinds.
        require(all(i.get('sequence',0)>=0xfffffffe for i in tx['vin']),'FUNDING_REPLACEABLE','Funding signals replacement')
        return self.id
