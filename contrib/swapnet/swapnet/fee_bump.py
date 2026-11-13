"""Explicit, bounded replacement of a claim or refund; never reprice principal.

Funding is non-RBF and is never automatically replaced. Replacement spending
transactions retain the same input, branch and beneficiary. EVM replacements
retain the same nonce, value, target and calldata. Owner-approved absolute caps
remain binding, including after mandate revocation.
"""
from .canonical import atoms
from .errors import require
from .terms import Agreement

def bump(coordinator,ctx,swap_id,kind,new_fee_atoms):
    require(kind in {'claim','refund'},'REPLACEMENT_KIND','Only claim/refund replacements are supported')
    rev,s=coordinator._owned(ctx,swap_id);agr=Agreement.parse(s['agreement'])
    own_name,own,in_name,incoming=coordinator._own(s,agr)
    leg=own if kind=='refund' else incoming;name=own_name if kind=='refund' else in_name
    key=s['keys']['refund' if kind=='refund' else 'claim'];driver=coordinator._driver(leg.asset)
    oid=s.get(kind+'_op');require(oid,'OPERATION_MISSING','No previously prepared spending operation')
    old=coordinator.journal.operation(oid);new=atoms(new_fee_atoms,positive=True)
    cap=atoms(leg.max_refund_fee_atoms if kind=='refund' else leg.max_claim_fee_atoms)
    require(atoms(old['metadata']['fee_atoms'])<new<=cap,'FEE_CAP','Replacement must increase fee within the signed cap')
    report=driver.observe(leg,s['refs'][name]);require(not report.observation.conflicting,'CHAIN_CONFLICT','Reconcile chain conflict first')
    if kind=='refund':
        now=report.clock.height if leg.lock_domain=='height' else report.clock.timestamp
        require(now>=leg.lock_value,'REFUND_EARLY','Refund is not mature')
        funding=coordinator.journal.operation(s['fund_op'])
        require(new+atoms(funding['metadata']['fee_atoms'])<=atoms(s['max_local_fee_atoms']),
                'FEE_CAP','Funding plus replacement refund exceeds local authorization')
    else:
        require(s['secret_exposed'],'SECRET_NOT_EXPOSED','Do not disclose a secret through a fee replacement')
    if driver.family=='evm':
        # Half the branch cap remains reserved for the mandatory pull withdrawal.
        require(new<=cap//2,'FEE_CAP','Replacement would consume withdrawal gas reserve')
        prepared=driver.replace(old,new_fee_atoms)
    elif kind=='refund':prepared=driver.prepare_refund(swap_id,leg,s['refs'][name],key,new_fee_atoms)
    else:
        template=driver.prepare_claim_template(swap_id,leg,s['refs'][name],key,new_fee_atoms,replacing=True)
        prepared=driver.finish_claim(leg,s['refs'][name],template,coordinator.vault.secret(swap_id,leg.hashlock))
    require(prepared.txid!=old['txid'],'REPLACEMENT_IDENTICAL','Replacement did not change transaction')
    metadata={**prepared.metadata,'reference':s['refs'][name],'fee_atoms':prepared.fee_atoms,'replacement_of':old['txid']}
    new_id=coordinator.journal.prepare(swap_id,leg.asset,kind,prepared.txid,prepared.raw,metadata)
    s[kind+'_op']=new_id;s['updated_at']=coordinator.now();coordinator.journal.save(swap_id,s,rev)
    coordinator.journal.checkpoint();coordinator.journal.broadcast(new_id,driver)
    return {'swap_id':swap_id,'kind':kind,'txid':prepared.txid,'replacement_of':old['txid'],
            'fee_atoms':prepared.fee_atoms,'beneficiary_changed':False}
