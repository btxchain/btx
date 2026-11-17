"""Real market Application + Store/Journal + signed messages, simulated chain
inventory only. No successful result here is labelled a funded-chain test.
"""
from pathlib import Path
import tempfile
import unittest
from swapnet.store import Store
from swapnet.market_application import Application
from swapnet.authorization import Principal
from swapnet.policy import Mandate
from swapnet.errors import SwapError
from test_public_market import Identity,NETWORK,BTX,BTC,NOW

class Driver:
    def __init__(self,family):self.family=family
    def ready(self):return True
    def inventory(self):return 1000

class ApplicationTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.messages=[];self.now=NOW;self.apps=[];self.owner=Principal('owner',True,'wallet')
        for n in range(2):
            directory=Path(self.tmp.name)/str(n);directory.mkdir(mode=0o700)
            store=Store(directory/'state.sqlite');identity=Identity('node'+str(n))
            def send(peer,command,raw,source=n):self.messages.append((source,peer,command,raw));return True
            app=Application(store,NETWORK,identity,None,{BTX:Driver('btx'),BTC:Driver('btc')},send,clock=lambda:self.now)
            self.apps.append(app)
        maker=self.apps[0];maker.rpc(self.owner,'setswapmode',{'mode':'maker'})
        mandate=Mandate('owner',BTC,'1000','500','10',NOW+3600,'3'*64)
        maker.store.install_mandate(mandate,owner_authorized=True)
        maker.rpc(self.owner,'setswapmarket',{'market':{'sell_asset':BTX,'buy_asset':BTC,'numerator':'2','denominator':'1','maker_fee_atoms':'1','max_receive_network_fee_atoms':'2','max_input_atoms':'200','expires_at':NOW+3600},
            'mandate_id':mandate.id,'max_local_fee_atoms':'10','refund_fee_atoms':'5','claim_fee_atoms':'5'})
        self.apps[0].peer_connected(1);self.apps[1].peer_connected(0);self.pump()
    def tearDown(self):
        for app in self.apps:app.close()
        self.tmp.cleanup()
    def pump(self):
        for _ in range(100):
            for app in self.apps:app.tick()
            if not self.messages:return
            messages,self.messages=self.messages,[]
            for source,target,command,raw in messages:self.apps[target].on_message(source,command,raw)
        self.fail('Wire did not quiesce')
    def offer(self):
        r=self.apps[0].rpc(self.owner,'publishswapoffer',{'sell_asset':BTX,'buy_asset':BTC,'sizes':['100'],'kind':'firm','slots':1,'ttl':120});self.pump();return r['offer']
    def test_default_observation_discovers_real_signed_offers(self):
        offer=self.offer();result=self.apps[1].rpc(self.owner,'listswappublicoffers',{})
        self.assertEqual(result['offers'],[offer]);self.assertEqual(self.apps[1].rpc(self.owner,'getswapmode',{})['mode'],'observe')
        self.assertEqual(self.apps[1].store.db.execute('SELECT count(*) FROM reservations').fetchone()[0],0)
    def test_public_offer_becomes_one_requester_bound_quote(self):
        offer=self.offer()['body'];taker=self.apps[1]
        r=taker.rpc(self.owner,'requestpublicswapquote',{'provider':offer['provider'],'offer_id':offer['offer_id'],'tier':0});self.pump()
        quotes=taker.rpc(self.owner,'getswapquotes',{'request_id':r['request_id']})['quotes']
        self.assertEqual(len(quotes),1);self.assertEqual(quotes[0]['minimum_receive_atoms'],'197')
        self.assertEqual(self.apps[0].store.db.execute("SELECT count(*) FROM sn_public_slots WHERE state='quoted'").fetchone()[0],1)
    def test_preview_never_creates_a_mandate_or_reservation(self):
        offer=self.offer()['body'];taker=self.apps[1]
        r=taker.rpc(self.owner,'requestpublicswapquote',{'provider':offer['provider'],'offer_id':offer['offer_id'],'tier':0});self.pump()
        quote=taker.rpc(self.owner,'getswapquotes',{'request_id':r['request_id']})['quotes'][0]
        preview=taker.rpc(self.owner,'previewswap',{'quote_id':quote['id'],'max_local_fee_atoms':'10'})
        self.assertFalse(preview['funds_reserved']);self.assertEqual(taker.store.db.execute('SELECT count(*) FROM mandates').fetchone()[0],0)
        with self.assertRaisesRegex(SwapError,'MODE_DISABLED'):taker.rpc(self.owner,'confirmswap',{'preview_id':preview['preview_id']})
        self.assertEqual(taker.store.db.execute('SELECT count(*) FROM reservations').fetchone()[0],0)
    def test_peer_cannot_invoke_owner_surface(self):
        reader=Principal('reader',False,'wallet')
        for method in ('publishswapoffer','connectswapinvite','confirmswap','setswapmode'):
            with self.assertRaisesRegex(SwapError,'OWNER_REQUIRED'):self.apps[1].rpc(reader,method,{})
    def test_network_payload_cannot_grant_rpc_authority(self):
        from swapnet.canonical import dumps
        with self.assertRaises(SwapError):self.apps[0].on_message(1,'swcap',dumps({'version':1,'network':NETWORK,'public_offers':1,'owner':True}).decode())
    def test_pausing_maker_stops_new_public_allocation(self):
        offer=self.offer()['body'];self.apps[0].rpc(self.owner,'setswapmode',{'mode':'observe'})
        r=self.apps[1].rpc(self.owner,'requestpublicswapquote',{'provider':offer['provider'],'offer_id':offer['offer_id'],'tier':0});self.pump()
        result=self.apps[1].rpc(self.owner,'getswapquotes',{'request_id':r['request_id']})
        self.assertEqual(result['quotes'],[]);self.assertEqual(result['declined']['code'],'MODE_DISABLED')
        self.assertTrue(self.apps[0].participation.info()['existing_obligations_recovery_enabled'])

if __name__=='__main__':unittest.main()
