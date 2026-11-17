"""Production SQLite/public-market regressions; signatures use an Ed25519 test
identity, not native P2MR. These tests do not claim funded-chain qualification.
"""
from __future__ import annotations
import base64
from dataclasses import asdict
from pathlib import Path
import tempfile
import unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from swapnet.store import Store
from swapnet.journal import Journal
from swapnet.policy import Mandate
from swapnet.quote import Quote
from swapnet.marketmaker import Maker,Market
from swapnet.public_market import PublicMarket,reserved_budget,reserved_inventory
from swapnet.canonical import digest
from swapnet.errors import SwapError
from swapnet import node_invites
from swapnet.market_lifecycle import Participation

NETWORK='1'*64
BTX='btx:'+NETWORK+':0:native'
BTC='btc:'+'2'*64+':0:native'
NOW=1700000000
KEYS={}
class Identity:
    def __init__(self,name):
        self.name=name;self.network=NETWORK;self.key=Ed25519PrivateKey.generate();KEYS[name]=self.key.public_key()
    def address(self):return self.name
    def peek(self):return self.name
    def sign(self,message):return base64.b64encode(self.key.sign(message.encode())).decode()
    def verify(self,address,signature,message):
        try:KEYS[address].verify(base64.b64decode(signature,validate=True),message.encode());return True
        except Exception:return False

class MarketTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.store=Store(Path(self.tmp.name)/'state.sqlite');self.journal=Journal(self.store)
        self.identity=Identity('maker');self.buyer=Identity('buyer');self.book=PublicMarket(self.store,self.journal,NETWORK,self.identity)
        self.market=Market(BTX,BTC,'2','1','1','2','1000',NOW+3600)
        self.mandate=Mandate('owner',BTC,'1000','1000','10',NOW+3600,'3'*64)
        self.store.install_mandate(self.mandate,owner_authorized=True)
        self.policy={'market':asdict(self.market),'mandate_id':self.mandate.id,'principal':'owner','wallet':'wallet',
                     'max_local_fee_atoms':'10','refund_fee_atoms':'5','claim_fee_atoms':'5'}
        self.maker=Maker(self.store,NETWORK,'maker',lambda address,message:self.identity.sign(message),self.identity.verify)
        self.maker.set_verified_inventory(BTC,'1000',NOW)
    def tearDown(self):self.store.close();self.tmp.cleanup()
    def rfq(self,nonce='4'*64):
        return {'network':NETWORK,'requester':digest('BTX/SWAPNET/REQUESTER/2',{'identity':'buyer','nonce':nonce}),
                'sell_asset':BTX,'buy_asset':BTC,'sell_atoms':'100','nonce':nonce,'issued_at':NOW,'expires_at':NOW+120}
    def publish(self,kind='firm',slots=2):return self.book.publish(self.policy,['100'],kind,slots,120,'1000',NOW)
    def test_signature_and_exact_terms(self):
        env=self.publish();self.assertEqual(env['body']['tiers'][0]['buy_atoms'],'200')
        self.assertEqual(self.book.page(NOW)['offers'],[env])
        env['body']['tiers'][0]['buy_atoms']='999'
        with self.assertRaisesRegex(SwapError,'BAD_SIGNATURE'):self.book.ingest(env,NOW)
    def test_capacity_is_not_double_allocated(self):
        env=self.publish(slots=1);b=env['body'];r=self.rfq()
        _,slot=self.book.allocate(b['offer_id'],b['sequence'],0,r,'buyer',NOW)
        self.assertEqual(self.book.allocate(b['offer_id'],b['sequence'],0,r,'buyer',NOW)[1],slot)
        with self.assertRaisesRegex(SwapError,'OFFER_CAPACITY'):self.book.allocate(b['offer_id'],b['sequence'],0,self.rfq('5'*64),'buyer',NOW)
    def test_public_capacity_blocks_unrelated_spending(self):
        self.publish()
        q=Quote(NETWORK,'unrelated','6'*64,'7'*64,1,BTC,BTX,'700','100','0','0',NOW,NOW+60)
        with self.assertRaisesRegex(SwapError,'BUDGET_LIMIT'):self.store.reserve(q,self.mandate.id,'owner','10',NOW)
    def test_exact_quote_transfer_is_atomic(self):
        env=self.publish();b=env['body'];rfq=self.rfq();_,slot=self.book.allocate(b['offer_id'],b['sequence'],0,rfq,'buyer',NOW)
        sq=self.maker.quote(rfq,self.market,NOW,public_slot=slot);q=sq.quote;self.book.bind_quote(slot,q,NOW)
        sid=digest('BTX/SWAPNET/SWAP/2',{'quote_id':q.id,'initiator':'buyer'})
        reverse=Quote(NETWORK,'buyer',digest('BTX/SWAPNET/MAKER/2',{'swap_id':sid}),q.nonce,q.sequence,BTC,BTX,'199','100','0','0',NOW,q.expires_at)
        rid=self.store.reserve(reverse,self.mandate.id,'owner','10',NOW)
        state=self.store.db.execute('SELECT state,reservation_id FROM sn_public_slots WHERE slot_id=?',(slot,)).fetchone()
        self.assertEqual(state,('reserved',rid));self.assertEqual(self.store.reserve(reverse,self.mandate.id,'owner','10',NOW),rid)
        self.assertEqual(self.store.db.execute('SELECT held FROM mandates WHERE id=?',(self.mandate.id,)).fetchone()[0],'209')
    def test_nonce_only_cannot_steal_a_capacity_credit(self):
        env=self.publish();b=env['body'];rfq=self.rfq();_,slot=self.book.allocate(b['offer_id'],b['sequence'],0,rfq,'buyer',NOW)
        q=self.maker.quote(rfq,self.market,NOW,public_slot=slot).quote;self.book.bind_quote(slot,q,NOW)
        forged=Quote(NETWORK,'buyer','8'*64,q.nonce,q.sequence,BTC,BTX,'199','100','0','0',NOW,q.expires_at)
        self.assertEqual(reserved_budget(self.store.db,self.mandate.id,forged,NOW),418)
    def test_withdrawal_keeps_requester_bound_quote(self):
        env=self.publish();b=env['body'];rfq=self.rfq();_,slot=self.book.allocate(b['offer_id'],b['sequence'],0,rfq,'buyer',NOW)
        q=self.maker.quote(rfq,self.market,NOW,public_slot=slot).quote;self.book.bind_quote(slot,q,NOW)
        withdrawn=self.book.withdraw(b['offer_id'],NOW+1)
        self.assertTrue(withdrawn['body']['withdrawn']);self.assertIsNotNone(self.book.policy_for_quote(q.id))
        with self.assertRaisesRegex(SwapError,'OFFER_REPLAY'):self.book.ingest(env,NOW+1)
    def test_expiry_releases_only_uncommitted_capacity(self):
        env=self.publish();self.book.close_expired(NOW+121)
        self.assertEqual(reserved_inventory(self.store.db,BTC,NOW+121),0)
        self.assertFalse(self.book.page(NOW+121)['offers'])
    def test_indicative_offer_does_not_reserve_inventory(self):
        self.publish('indicative');self.assertEqual(reserved_inventory(self.store.db,BTC,NOW),0)
    def test_total_mandate_and_inventory_caps(self):
        with self.assertRaisesRegex(SwapError,'INSUFFICIENT_LIQUIDITY'):self.book.publish(self.policy,['100'],'firm',6,120,'1000',NOW)
        self.book.publish(self.policy,['100'],'firm',4,120,'1000',NOW)
        with self.assertRaises(SwapError):self.book.publish(self.policy,['100'],'firm',2,120,'1000',NOW)
    def test_reopen_retains_allocated_capacity(self):
        env=self.publish(slots=1);b=env['body'];self.book.allocate(b['offer_id'],b['sequence'],0,self.rfq(),'buyer',NOW)
        self.store.close();self.store=Store(Path(self.tmp.name)/'state.sqlite');self.journal=Journal(self.store);self.book=PublicMarket(self.store,self.journal,NETWORK,self.identity)
        with self.assertRaisesRegex(SwapError,'OFFER_CAPACITY'):self.book.allocate(b['offer_id'],b['sequence'],0,self.rfq('9'*64),'buyer',NOW)
    def test_pagination_does_not_stop_at_32(self):
        for i in range(40):self.publish('indicative')
        page1=self.book.page(NOW,limit=32);self.assertEqual(len(page1['offers']),32)
        page2=self.book.page(NOW,after=page1['next_cursor'],limit=32);self.assertEqual(len(page2['offers']),8)
        self.assertIsNone(page2['next_cursor'])
    def test_default_mode_has_no_spending_authority(self):
        p=Participation(self.journal);self.assertEqual(p.info()['mode'],'observe');self.assertEqual(p.info()['automatic_spend_atoms'],'0')
        with self.assertRaises(SwapError):p.require_trade()
        p.set('maker');self.assertTrue(p.may_make());p.set('observe');self.assertTrue(p.info()['existing_obligations_recovery_enabled'])
    def test_startup_recovery_lock_cannot_be_cleared_by_rpc(self):
        p=Participation(self.journal,'recovery')
        with self.assertRaisesRegex(SwapError,'MODE_LOCKED'):p.set('maker')
    def test_signed_invitation_is_inert_and_chain_bound(self):
        created=node_invites.create(self.identity,NETWORK,['93.184.216.34:29447'],NOW)
        view=node_invites.inspect(created['uri'],NETWORK,NOW,self.identity.verify)
        self.assertFalse(view['connection_started']);self.assertFalse(view['spending_authority']);self.assertFalse(view['transport_identity_proven'])
        with self.assertRaisesRegex(SwapError,'NETWORK'):node_invites.inspect(created['uri'],'f'*64,NOW,self.identity.verify)
    def test_invitation_private_scope_and_unsafe_endpoints(self):
        for ep in ['127.0.0.1:8332','169.254.169.254:80','0.0.0.0:1','[::1]:8333','example.com:1/path','user@example.com:1']:
            with self.assertRaises(SwapError):node_invites.endpoint(ep,allow_private=True)
        with self.assertRaisesRegex(SwapError,'INVITE_PRIVATE'):node_invites.endpoint('192.168.1.2:8333')
        self.assertTrue(node_invites.endpoint('192.168.1.2:8333',allow_private=True)['private'])
    def test_invitation_rejects_tamper_and_expiry(self):
        created=node_invites.create(self.identity,NETWORK,['93.184.216.34:29447'],NOW,ttl=60)
        with self.assertRaisesRegex(SwapError,'INVITE_EXPIRED'):node_invites.inspect(created['uri'],NETWORK,NOW+60,self.identity.verify)
        with self.assertRaises(SwapError):node_invites.inspect(created['uri']+'=',NETWORK,NOW,self.identity.verify)

if __name__=='__main__':unittest.main()
