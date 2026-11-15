from dataclasses import replace
import pytest
from swapnet.machine import *
from swapnet.policy import *
from swapnet.errors import SwapError
from conftest import NOW
P=SafetyPolicy()
A=ChainClock('btx',1000,NOW,NOW,60,120)
B=ChainClock('btc',1000,NOW,NOW,300,900)
LONG=Deadline('height',2000);SHORT=Deadline('height',1020)
EMPTY=LegObservation(observed_at=NOW)
FUNDED_A=LegObservation(True,True,True,20,observed_at=NOW)
FUNDED_B=LegObservation(True,True,True,6,observed_at=NOW)
def act(s,a=EMPTY,b=EMPTY,ca=A,cb=B):return decide(s,a,b,ca,cb,LONG,SHORT,P,NOW)
def test_no_implicit_spend():assert act(Session('1'*64,'initiator'))=='await_authorization'
def test_initiator_funds_first():
    s=Session('1'*64,'initiator');s.authorize();assert act(s)=='prepare_long_funding_and_recovery'
def test_responder_requires_confirmed_funding():
    s=Session('1'*64,'responder');s.authorize()
    assert act(s)=='wait_for_chain'
    assert act(s,replace(FUNDED_A,confirmations=19))=='wait_for_chain'
    assert act(s,FUNDED_A)=='prepare_short_funding_and_recovery'
def test_recovery_before_reveal():
    s=Session('1'*64,'initiator')
    with pytest.raises(SwapError):act(s,FUNDED_A,FUNDED_B)
    s.recovery_ready=True;assert act(s,FUNDED_A,FUNDED_B)=='persist_secret_exposure_then_claim_short_leg'
def test_secret_exposed_survives_reorg():
    s=Session('1'*64,'responder');s.mark_exposed()
    assert act(s,FUNDED_A,EMPTY)=='claim_long_leg'
    assert s.secret_exposed
@pytest.mark.parametrize('change',[{'canonical':False},{'exact_terms':False},{'confirmations':0}])
def test_never_reveal_unverified_short(change):
    s=Session('1'*64,'initiator',recovery_ready=True)
    assert act(s,FUNDED_A,replace(FUNDED_B,**change))!='persist_secret_exposure_then_claim_short_leg'
def test_refund_is_available_after_expiry():
    s=Session('1'*64,'initiator');assert act(s,FUNDED_A,EMPTY,replace(A,height=2001))=='refund_local_leg'
def test_stale_observation_blocks():
    with pytest.raises(SwapError):act(Session('1'*64,'initiator'),replace(EMPTY,observed_at=NOW-61))
def test_stalled_chain_blocks():
    with pytest.raises(SwapError):act(Session('1'*64,'initiator'),ca=replace(A,stalled=True))
def test_timeout_domains():
    with pytest.raises(SwapError):Deadline('height',500000000)
    with pytest.raises(SwapError):P.validate_deadlines(Deadline('height',1030),SHORT,A,B,NOW)
def test_two_final_claims_complete():
    assert act(Session('1'*64,'initiator'),replace(FUNDED_A,claimed=True),replace(FUNDED_B,claimed=True))=='complete'
def test_evm_requires_finalized():
    assert not LegObservation(True,True,True,100,False,observed_at=NOW).settled('evm',P,NOW)
