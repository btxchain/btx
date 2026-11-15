from dataclasses import asdict,replace
import hashlib,hmac
import pytest
from swapnet.discovery import Catalog
from swapnet.canonical import digest
from swapnet.service import Service,Context,METHODS
from swapnet.quote import SignedQuote
from swapnet.errors import SwapError
from conftest import NOW,NET,BTX,BTC
# TEST ONLY identity stand-in. Runtime MUST use btxd BIP-322 verification.
def signature(identity,message):return hmac.new(b'test-only-fixture',f'{identity}:{message}'.encode(),hashlib.sha256).hexdigest()
def verify(identity,sig,message):return hmac.compare_digest(sig,signature(identity,message))
def provider(seq=1):
    b={'version':1,'network':NET,'identity':'maker','sequence':seq,'issued_at':NOW,'expires_at':NOW+300,
       'pairs':[{'sell':BTX,'buy':BTC}],'settlement':['sha256-htlc-v1']}
    return {'body':b,'signature':signature('maker','BTX/SWAPNET/PROVIDER/1:'+digest('BTX/SWAPNET/PROVIDER/1',b))}
def test_catalog_replay_and_search(store):
    c=Catalog(store,NET,verify);assert c.ingest(provider(),NOW)=='maker'
    assert len(c.search(NOW,BTX,BTC)['providers'])==1
    with pytest.raises(SwapError):c.ingest(provider(),NOW)
    c.ingest(provider(2),NOW)
    assert c.search(NOW+301)['providers']==[]
def test_bad_identity_signature(store):
    c=Catalog(store,NET,verify);e=provider();e['signature']='wrong'
    with pytest.raises(SwapError):c.ingest(e,NOW)
def test_rpc_workflow_and_default_guard(store,quote,mandate):
    out=[];s=Service(store,NET,verify,clock=lambda:NOW,enqueue=lambda *v:out.append(v))
    ctx=Context('agent',frozenset({'owner','read','quote','trade','audit'}))
    mid=s.dispatch(ctx,'createswapmandate',{'mandate':asdict(mandate)})['mandate_id']
    rfq=s.dispatch(ctx,'requestswapquote',{'sell_asset':BTX,'buy_asset':BTC,'sell_atoms':'10000','nonce':'1'*64})
    q=replace(quote,requester=rfq['requester']);env=SignedQuote(q,signature(q.provider,q.signing_message)).as_dict()
    s.ingest_quote(env,rfq['request_id'])
    assert s.dispatch(ctx,'getswapquotes',{'request_id':rfq['request_id']})['quotes'][0]['minimum_receive_atoms']=='19700'
    params={'quote_id':q.id,'mandate_id':mid,'max_local_fee_atoms':'100'}
    accepted=s.dispatch(ctx,'acceptswapquote',params)
    assert s.dispatch(ctx,'acceptswapquote',params)==accepted
    sid=accepted['id'];assert accepted['state']['funding_broadcast'] is False
    with pytest.raises(SwapError):s.dispatch(ctx,'resumeswap',{'swap_id':sid})
    s.dispatch(ctx,'cancelswap',{'swap_id':sid});assert store.db.execute('SELECT held FROM mandates').fetchone()[0]=='0'
    assert out[0][0]=='swrfq'
def test_read_scope_cannot_create_budget(store,mandate):
    s=Service(store,NET,verify);ctx=Context('agent',frozenset({'read'}))
    with pytest.raises(SwapError):s.dispatch(ctx,'createswapmandate',{'mandate':asdict(mandate)})
    assert s.dispatch(ctx,'getswapnetworkinfo')['automatic_spend_atoms']=='0'
def test_rpc_json_owner_flag_does_not_grant_authority(store,mandate):
    s=Service(store,NET,verify)
    with pytest.raises(SwapError):s.dispatch({'principal':'owner','capabilities':['owner']},'createswapmandate',{'mandate':asdict(mandate)})
def test_all_rpcs_have_concrete_handler(store):
    s=Service(store,NET,verify)
    for method in METHODS:assert callable(getattr(s,'rpc_'+method))
