from dataclasses import replace
from decimal import Decimal
import pytest
from swapnet.plans import FundingPlan
from swapnet.terms import Agreement,LegTerms
from swapnet.adapters import to_atoms,BTXAdapter
from swapnet.errors import SwapError
from swapnet.vault import ForeignKeyVault
from conftest import NET,BTX,BTC

def test_funding_plan_binds_all_outputs():
    p=FundingPlan(NET,'1'*64,'2'*64,BTX,('a'*64+':0',),'20000',(('51','10000','htlc'),('52','9000','change')),'1000')
    tx={'locktime':0,'vin':[{'txid':'a'*64,'vout':0,'sequence':0xffffffff}],
        'vout':[{'value':Decimal('0.00010000'),'scriptPubKey':{'hex':'51'}},{'value':Decimal('0.00009000'),'scriptPubKey':{'hex':'52'}}]}
    assert p.verify_decoded(tx,is_owned_change=lambda s:s=='52',atoms_from_rpc=to_atoms)==p.id
    tx['vout'][1]['scriptPubKey']['hex']='53'
    with pytest.raises(SwapError):p.verify_decoded(tx,is_owned_change=lambda s:True,atoms_from_rpc=to_atoms)
def test_pq_key_not_ec_key():
    b=BTXAdapter(lambda *a:None,lambda *a:None,NET)
    with pytest.raises(SwapError):b.descriptor('c'*64,'02'+'a'*64,'03'+'b'*64,1000)
def test_agreement_binds_quote_and_both_legs(quote):
    a=LegTerms(BTX,'10000','c'*64,'pq1','pq2','payout1','refund1','height',10000,'script1','50','50')
    b=LegTerms(BTC,'19900','c'*64,'ec1','ec2','payout2','refund2','height',20000,'script2','200','100')
    ag=Agreement(NET,quote.id,'alice','maker','f'*64,a,b)
    assert ag.verify(quote,{'initiator':'test','responder':'test'},lambda *a:True)
    with pytest.raises(SwapError):replace(ag,short_leg=replace(b,amount_atoms='18000')).verify(quote,{'initiator':'test','responder':'test'},lambda *a:True)
def test_secret_vault_scope(tmp_path):
    v=ForeignKeyVault(tmp_path/'vault',b'test-strong-passphrase-1234');h=v.new_secret('1'*64)
    assert len(v.secret('1'*64,h))==32
    with pytest.raises(SwapError):v.new_secret('1'*64)
    with pytest.raises(SwapError):v.secret('2'*64,h)
