"""Owner-visible local execution metrics. Never presented as global proof of liquidity."""
from collections import defaultdict
from .market_controls import amount, require

TERMINAL={'complete','refunded','cancelled','rejected'}
def local_market_health(sessions):
    by_pair={};seen=set()
    for sid,_,s in sessions:
        if sid in seen:continue
        seen.add(sid)
        env=s.get('quote',{});q=env.get('quote',{})
        if not all(k in q for k in ('sell_asset','buy_asset','sell_atoms','buy_atoms','provider')):continue
        key=(q['sell_asset'],q['buy_asset'])
        row=by_pair.setdefault(key,{'sell_asset':key[0],'buy_asset':key[1],'complete':0,'refunded':0,'cancelled':0,'rejected':0,
                                   'pending_or_unknown':0,'settled_sell_atoms':0,'providers':defaultdict(int)})
        stage=s.get('stage')
        if stage in TERMINAL:row[stage]+=1
        else:row['pending_or_unknown']+=1
        if stage=='complete':
            n=amount(q['sell_atoms'],positive=True);row['settled_sell_atoms']+=n;row['providers'][q['provider']]+=n
    output=[]
    for _,r in sorted(by_pair.items()):
        total=r['settled_sell_atoms'];providers=r.pop('providers')
        r['settled_sell_atoms']=str(total)
        r['settled_volume_by_provider_identity']=[{'identity':p,'sell_atoms':str(n)} for p,n in sorted(providers.items())]
        r['identity_hhi_bps']=None if not total else sum(n*n for n in providers.values())*10000//(total*total)
        output.append(r)
    return {'markets':output,'scope':'this_node_owned_session_history','independent_owners_proven':False,
            'proof_of_reserves':False,'timeouts_imply_misconduct':False,'reorg_sensitive':True}


def settlement_receipt(sid,s):
    """Opt-in disclosure of public terms and tx references, not witnesses or keys.
    Caller MUST first enforce session principal/wallet ownership.
    """
    require(s.get('stage') in {'complete','refunded'},'NOT_TERMINAL','No final local outcome to export')
    from dataclasses import asdict
    from .terms import Agreement
    from .quote import Quote
    agr=asdict(Agreement.parse(s['agreement']))
    q={'quote':asdict(Quote.parse(s['quote']['quote'])),'signature':s['quote']['signature']}
    refs={}
    for name,ref in s.get('refs',{}).items():
        if isinstance(ref,dict):refs[name]={k:ref[k] for k in ('txid','vout','lock_id','blockhash') if k in ref}
    return {'schema':'BTX/SWAPNET/RECEIPT/1','swap_id':sid,'quote':q,
            'agreement':agr,'agreement_signatures':{k:v for k,v in s.get('signatures',{}).items() if k in {'initiator','responder'}},'transaction_references':refs,
            'reported_outcome':s['stage'],'reported_at':s.get('updated_at'),
            'verification':'locally_observed; independently verify both chains',
            'privacy':'Opt-in disclosure links counterparties, prices and chain transactions',
            'proof_of_reserves':False,'secret_or_raw_transaction_included':False}
