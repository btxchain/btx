"""A restored BTX session must not pay its lock a second time.

#666 fences a restored Bitcoin session behind its wallet history. The BTX leg of
a restored session still used only the unspent scan, so a lock that the old node
had funded and that is no longer unspent (claimed, refunded, or not yet in the
UTXO set) was funded again under the same hashlock.
"""
from decimal import Decimal
import pytest
from test_execution_v2 import pair,A
from test_funding_scan_and_capacity import TXID
from test_restored_history import History,Probe
from swapnet.errors import SwapError

def restored_btx(p,mode,restored=True):
 p.start();p.deliver();c=p.nodes['alice'][3];h=History(mode);leg=p.state('alice')['agreement']['long_leg'];h.script=leg['lock_commitment'];h.coin=Decimal(leg['amount_atoms'])/100000000;d=Probe(c.drivers[A],h);c.drivers[A]=d
 if restored:p.nodes['alice'][1].set_setting('restored_session:'+p.sid,True)
 assert d.family=='btx'
 return c,d,h

def test_restored_btx_adopts_historical_lock(pair):
 c,d,h=restored_btx(pair,'unique');c.tick_one(pair.sid);c.tick_one(pair.sid)
 assert d.funding_calls==0 and h.history_calls>0
 assert pair.state('alice')['refs']['a']=={'txid':TXID,'vout':0}
 assert not [o for o in pair.nodes['alice'][1].operations(pair.sid) if o['kind']=='fund']

@pytest.mark.parametrize('mode',['missing','incomplete','ambiguous','empty'])
def test_restored_btx_without_clear_history_never_funds(pair,mode):
 c,d,h=restored_btx(pair,mode)
 with pytest.raises(SwapError) as error:c.tick_one(pair.sid)
 assert error.value.code=={'missing':'CHAIN_RPC','incomplete':'FUNDING_LOOKUP','ambiguous':'FUNDING_AMBIGUOUS','empty':'RECOVERY_UNRESOLVED'}[mode]
 assert d.funding_calls==0 and not pair.state('alice')['funding_broadcast']

def test_fresh_btx_session_funds(pair):
 c,d,h=restored_btx(pair,'missing',False);c.tick_one(pair.sid);c.tick_one(pair.sid)
 assert d.funding_calls==1 and pair.state('alice')['funding_broadcast'] and h.history_calls==0

def test_restored_btx_unspent_lock_needs_no_history(pair):
 c,d,h=restored_btx(pair,'missing');h.add(TXID,0);c.tick_one(pair.sid);c.tick_one(pair.sid)
 assert d.funding_calls==0 and h.history_calls==0
 assert pair.state('alice')['refs']['a']=={'txid':TXID,'vout':0}
