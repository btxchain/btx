from dataclasses import replace
import pytest
from swapnet.marketmaker import Maker,Market
from swapnet.errors import SwapError
from conftest import NET,NOW,BTX,BTC
from test_service import signature,verify

def setup(store):
 m=Maker(store,NET,'maker',signature,verify)
 market=Market(BTX,BTC,'2','1','100','200','20000',NOW+3600)
 rfq={'network':NET,'requester':'c'*64,'sell_asset':BTX,'buy_asset':BTC,'sell_atoms':'10000','nonce':'d'*64,'issued_at':NOW,'expires_at':NOW+120}
 m.set_verified_inventory(BTC,'25000',NOW)
 return m,market,rfq

def test_inventory_reserved_not_overquoted(store):
 m,market,r=setup(store);q=m.quote(r,market,NOW);assert q.quote.buy_atoms=='20000'
 assert m.quote(r,market,NOW).quote.id==q.quote.id
 with pytest.raises(SwapError):m.quote({**r,'nonce':'e'*64},market,NOW)

def test_expiry_releases_unaccepted_quote(store):
 m,market,r=setup(store);m.quote(r,market,NOW)
 m.set_verified_inventory(BTC,'25000',NOW+61)
 assert m.quote({**r,'nonce':'e'*64,'issued_at':NOW+61,'expires_at':NOW+180},market,NOW+61)

def test_stale_inventory_blocks(store):
 m,market,r=setup(store)
 with pytest.raises(SwapError):m.quote(r,market,NOW+31)

def test_expired_price_blocks(store):
 m,market,r=setup(store)
 with pytest.raises(SwapError):m.quote(r,replace(market,expires_at=NOW),NOW)
