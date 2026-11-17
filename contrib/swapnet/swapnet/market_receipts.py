"""Opt-in signed receipts with independent configured-node reobservation.

An exporter signature authenticates an account of execution, not consensus.
Verification checks the original two-party terms and asks this verifier's own
chain drivers. Timeout observations never become proof of malicious refusal.
No raw claim transaction, secret, private handle, or wallet credential is exported.
"""
from __future__ import annotations
from dataclasses import asdict
from .canonical import digest,exact_fields,hex32,integer,dumps
from .quote import Quote,SignedQuote
from .terms import Agreement
from .errors import require,SwapError

DOMAIN='BTX/SWAPNET/SETTLEMENT-RECEIPT/1'
FIELDS={'version','network','exporter','swap_id','issued_at','quote','agreement','signatures','references','reported_outcome','observations'}


def message(body):return DOMAIN+':'+digest(DOMAIN,body)


def export_receipt(app,ctx,swap_id):
    _,state=app.coordinator._owned(ctx,hex32(swap_id))
    require(state.get('agreement') and state.get('signatures'),'AGREEMENT_MISSING','No bilateral agreement yet')
    quote=state['quote'];agreement=state['agreement']
    # Select explicit safe fields, never copy the whole financial session.
    refs={}
    for leg,ref in state.get('refs',{}).items():
        if leg in {'a','b'} and type(ref) is dict:
            refs[leg]={k:v for k,v in ref.items() if k in {'txid','vout','lock_id','salt','blockhash','height'}}
    body={'version':1,'network':app.network,'exporter':app.identity.address(),'swap_id':swap_id,
          'issued_at':app.now(),'quote':quote,'agreement':agreement,'signatures':state['signatures'],
          'references':refs,'reported_outcome':state['stage'],'observations':state.get('observations',{})}
    require(len(dumps(body))<=60000,'RECEIPT_SIZE','Receipt exceeds export bound')
    return {'body':body,'signature':app.identity.sign(message(body)),
            'assurance':'signed account; reobserve with independent chain clients',
            'privacy':'explicit local export; no network publication'}


def verify_receipt(app,receipt):
    exact_fields(receipt,{'body','signature','assurance','privacy'})
    b=receipt['body'];exact_fields(b,FIELDS)
    require(type(b['version']) is int and b['version']==1,'RECEIPT_VERSION','Unsupported receipt')
    require(hex32(b['network'])==app.network,'NETWORK','Wrong receipt chain')
    integer(b['issued_at']);hex32(b['swap_id'])
    require(b['issued_at']<=app.now()+60,'RECEIPT_TIME','Receipt is future-dated')
    require(type(receipt['signature']) is str and len(receipt['signature'])<=16384,
            'SIGNATURE','Invalid receipt signature')
    require(app.identity.verify(b['exporter'],receipt['signature'],message(b)) is True,
            'BAD_SIGNATURE','Receipt signature rejected')
    q=Quote.parse(b['quote']['quote'])
    require(app.identity.verify(q.provider,b['quote']['signature'],q.signing_message) is True,
            'BAD_SIGNATURE','Original quote signature rejected')
    agreement=Agreement.parse(b['agreement'])
    agreement.verify(q,b['signatures'],app.identity.verify)
    require(b['swap_id']==digest('BTX/SWAPNET/SWAP/2',{'quote_id':q.id,'initiator':agreement.initiator}),
            'RECEIPT_BINDING','Receipt swap identifier differs from agreement')
    results={}
    for name,terms in (('a',agreement.long_leg),('b',agreement.short_leg)):
        try:
            driver=app.coordinator._driver(terms.asset)
            ref=b['references'].get(name)
            require(ref is not None,'REFERENCE_MISSING','Receipt omits funding reference')
            verify_reference=getattr(driver,'verify_reference',None)
            if verify_reference is not None:verify_reference(b['swap_id'],terms,ref)
            report=driver.observe(terms,ref)
            observation=report.observation
            results[name]={'available':True,'asset':terms.asset,
                           'observation':asdict(observation),
                           'settled':observation.settled(driver.family,app.coordinator.policy,app.now())}
        except (SwapError,KeyError,ValueError,TypeError,AttributeError) as error:
            results[name]={'available':False,'asset':terms.asset,
                           'error':getattr(error,'code','VERIFICATION_UNAVAILABLE')}
    independently_claimed=all(x.get('available') and x.get('settled') and all(x.get('observation',{}).get(k) for k in ('exists','exact','canonical','claimed')) for x in results.values())
    has_evm=any(str(x.get('asset','')).startswith('evm:') for x in results.values())
    return {'receipt_signature_verified':True,'bilateral_terms_verified':True,
            'independently_claimed_htlcs':independently_claimed,
            'wallet_delivery_verified':independently_claimed and not has_evm,
            'evm_withdrawal_assurance':'contract credits are fungible; separate wallet reconciliation is required' if has_evm else None,
            'reported_outcome':b['reported_outcome'],
            'legs':results,'checked_at':app.now(),
            'assurance':'current observations from locally configured independent drivers; not a portable consensus proof',
            'reorg_sensitive':True}
