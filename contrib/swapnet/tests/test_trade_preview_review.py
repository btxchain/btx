"""Stored native-review terms; real Application/SQLite, simulated chain drivers.

No native node, funded chain, or Atlas dialog is exercised by these tests.
"""
from pathlib import Path
import json
import sqlite3
import unittest
from unittest.mock import patch

from swapnet.authorization import Principal
from swapnet.canonical import dumps, loads
from swapnet.embedded import Host
from swapnet.errors import SwapError
from swapnet.market_application import Application
from swapnet.store import Store
from swapnet.vault import ForeignKeyVault
import test_market_application as market_fixture
from test_public_market import BTX, BTC, NETWORK
from test_execution_v2 import Driver as ExecutionDriver, Ledger


class TradePreviewReviewTest(unittest.TestCase):
    setUp=market_fixture.ApplicationTest.setUp
    tearDown=market_fixture.ApplicationTest.tearDown
    pump=market_fixture.ApplicationTest.pump
    offer=market_fixture.ApplicationTest.offer

    def test_capabilities_expose_one_owner_scoped_preview_lookup(self):
        methods=self.apps[1].rpc(self.owner,'getswapcapabilities',{})['methods']
        self.assertEqual([m for m in methods if m['name']=='getswaptradepreview'],
                         [{'name':'getswaptradepreview','scope':'owner'}])
        self.assertEqual(len(methods),56)

    def preview(self):
        offer=self.offer()['body'];self.taker=self.apps[1]
        request=self.taker.rpc(self.owner,'requestpublicswapquote',
            {'provider':offer['provider'],'offer_id':offer['offer_id'],'tier':0})
        self.pump()
        quote=self.taker.rpc(self.owner,'getswapquotes',{'request_id':request['request_id']})['quotes'][0]
        self.original=self.taker.rpc(self.owner,'previewswap',
            {'quote_id':quote['id'],'max_local_fee_atoms':'10','refund_fee_atoms':'5',
             'claim_fee_atoms':'2','min_receive_atoms':'196'})
        self.pid=self.original['preview_id'];self.qid=quote['id'];self.quote_expires=quote['expires_at']
        return self.original

    def lookup(self,ctx=None):
        return self.taker.rpc(ctx or self.owner,'getswaptradepreview',{'preview_id':self.pid})

    def snapshot(self):
        return (tuple(self.taker.store.db.iterdump()),self.taker.store.db.total_changes)

    def test_exact_allowlist_and_read_only_terms(self):
        original=self.preview();before=self.snapshot()
        with (patch.object(self.taker,'_quote_for',side_effect=AssertionError('No live quote validation')),
              patch.object(self.taker.identity,'address',side_effect=AssertionError('No identity creation'))):
            result=self.lookup()
        self.assertEqual(result,{'preview_id':self.pid,'quote_id':self.qid,'principal':'owner','wallet':'wallet',
            'provider':'node0','sell_asset':BTX,'buy_asset':BTC,'sell_atoms':'100','buy_atoms':'200',
            'maximum_send_atoms':'110','minimum_receive_atoms':'196','net_receive_floor_atoms':'197',
            'max_local_fee_atoms':'10','refund_fee_atoms':'5','claim_fee_atoms':'2',
            'maker_fee_atoms':'1','max_receive_network_fee_atoms':'2',
            'expires_at':original['expires_at'],'quote_expires_at':self.quote_expires})
        self.assertEqual(self.snapshot(),before)
        self.assertFalse({'mandate','nonce','signature','quote','secret'} & result.keys())

    def test_owner_principal_wallet_and_request_shape_refusals(self):
        self.preview()
        for ctx,code in ((Principal('owner',False,'wallet'),'OWNER_REQUIRED'),
                         (Principal('other',True,'wallet'),'FORBIDDEN'),
                         (Principal('owner',True,'other'),'FORBIDDEN')):
            with self.subTest(ctx=ctx),self.assertRaisesRegex(SwapError,code):self.lookup(ctx)
        for params,code in (({'preview_id':'f'*64},'FORBIDDEN'),({'preview_id':'A'*64},'HEX32'),
                            ({'preview_id':self.pid,'summary':{}},'PARAMS'),({},'PARAMS')):
            with self.subTest(params=params),self.assertRaisesRegex(SwapError,code):
                self.taker.rpc(self.owner,'getswaptradepreview',params)

    def test_contradictory_and_malformed_local_terms_are_not_displayed(self):
        self.preview();row=self.taker.store.db.execute('SELECT body FROM sn_trade_previews WHERE id=?',(self.pid,)).fetchone()[0]
        cases={'sell_atoms':'101','buy_asset':BTX,'provider':'wrong','maximum_send_atoms':'111',
               'net_receive_floor_atoms':'198','minimum_receive_atoms':'198','refund_fee_atoms':'11',
               'claim_fee_atoms':'3','expires_at':self.original['expires_at']+1}
        for key,value in cases.items():
            with self.subTest(field=key):
                body=loads(row);body[key]=value
                self.taker.store.db.execute('UPDATE sn_trade_previews SET body=? WHERE id=?',(dumps(body),self.pid))
                before=self.snapshot()
                with self.assertRaisesRegex(SwapError,'PREVIEW_STATE'):self.lookup()
                self.assertEqual(self.snapshot(),before)
        self.taker.store.db.execute('UPDATE sn_trade_previews SET body=? WHERE id=?',(b'{',self.pid))
        with self.assertRaisesRegex(SwapError,'PREVIEW_STATE'):self.lookup()

    def test_expired_lookup_is_historical_but_new_confirmation_still_refuses(self):
        original=self.preview();self.now+=121;before=self.snapshot()
        result=self.lookup();self.assertEqual(result['expires_at'],original['expires_at'])
        self.assertEqual(self.snapshot(),before)
        with self.assertRaisesRegex(SwapError,'PREVIEW_EXPIRED'):
            self.taker.rpc(self.owner,'confirmswap',{'preview_id':self.pid})
        self.assertEqual(self.snapshot(),before)

    def host(self,bound):
        host=Host.__new__(Host);host._wallet=bound;host.app=self.taker;host.journal=self.taker.journal
        host.native=lambda *args: (_ for _ in ()).throw(AssertionError('Lookup must not call native RPC'))
        return host

    def test_unbound_and_bound_host_reads_do_not_bind_probe_or_write(self):
        self.preview()
        for bound in (None,'wallet'):
            with self.subTest(bound=bound):
                host=self.host(bound);before=self.snapshot()
                result=json.loads(host.rpc('owner',True,'wallet','getswaptradepreview',json.dumps({'preview_id':self.pid})))
                self.assertNotIn('error',result);self.assertEqual(result['result']['wallet'],'wallet')
                self.assertEqual(host._wallet,bound);self.assertEqual(self.snapshot(),before)
                wrong=json.loads(host.rpc('owner',True,'other','getswaptradepreview',json.dumps({'preview_id':self.pid})))
                self.assertIn(wrong['error']['code'],('WALLET_SCOPE','FORBIDDEN'))
                reader=json.loads(host.rpc('owner',False,'wallet','getswaptradepreview',json.dumps({'preview_id':self.pid})))
                self.assertEqual(reader['error']['code'],'OWNER_REQUIRED')
                blank=json.loads(host.rpc('owner',True,None,'getswaptradepreview',json.dumps({'preview_id':self.pid})))
                if bound:self.assertEqual(blank['result']['wallet'],bound)
                else:self.assertEqual(blank['error']['code'],'FORBIDDEN')
                self.assertEqual(host._wallet,bound);self.assertEqual(self.snapshot(),before)

    def test_other_host_method_keeps_existing_wallet_binding(self):
        self.preview();host=self.host(None);calls=[]
        host.native=lambda *args: (calls.append(args) or ['wallet'])
        result=json.loads(host.rpc('owner',True,'wallet','getswapmode','{}'))
        self.assertNotIn('error',result);self.assertEqual(calls,[('listwallets',)])
        self.assertEqual(host._wallet,'wallet');self.assertEqual(host.journal.setting('native_wallet'),'wallet')

    def test_started_trade_lost_preview_receipt_reopens_and_retries_after_expiry(self):
        self.preview();taker=self.taker
        ledgers={a:Ledger(a,lambda:self.now) for a in (BTX,BTC)}
        drivers={a:ExecutionDriver(ledger,'node1') for a,ledger in ledgers.items()}
        vault=ForeignKeyVault(Path(self.tmp.name)/'1/foreign-vault.json',b'x'*32)
        taker.drivers=drivers;taker.vault=vault;taker.coordinator.drivers=drivers;taker.coordinator.vault=vault
        # Fail after the real coordinator saved its initial trade/reservation,
        # exactly where confirmswap records its reply-recovery pointer.
        taker.store.db.execute("CREATE TRIGGER review_fail BEFORE UPDATE ON sn_trade_previews BEGIN SELECT RAISE(ABORT,'injected preview receipt save'); END")
        with self.assertRaisesRegex(sqlite3.IntegrityError,'injected preview receipt save'):
            taker.rpc(self.owner,'confirmswap',{'preview_id':self.pid})
        self.assertEqual(taker.store.db.execute('SELECT count(*) FROM sn_negotiations').fetchone()[0],1)
        self.assertIsNone(taker.store.db.execute('SELECT swap_id FROM sn_trade_previews WHERE id=?',(self.pid,)).fetchone()[0])
        held=tuple(taker.store.db.execute('SELECT id,held,used FROM mandates ORDER BY id'))
        keys={a:d.key_n for a,d in drivers.items()}
        sid=taker.store.db.execute('SELECT id FROM sn_negotiations').fetchone()[0]
        taker.store.db.execute('DROP TRIGGER review_fail');self.now+=121
        identity=taker.identity;send=taker.send;taker.close()
        self.taker=Application(Store(Path(self.tmp.name)/'1/state.sqlite'),NETWORK,identity,
            ForeignKeyVault(Path(self.tmp.name)/'1/foreign-vault.json',b'x'*32),drivers,send,clock=lambda:self.now)
        self.apps[1]=self.taker;before=self.snapshot();result=self.lookup()
        self.assertEqual(result['preview_id'],self.pid);self.assertEqual(self.snapshot(),before)
        retry=self.taker.rpc(self.owner,'confirmswap',{'preview_id':self.pid})
        self.assertEqual(retry['swap_id'],sid)
        self.assertEqual(self.taker.store.db.execute('SELECT count(*) FROM sn_negotiations').fetchone()[0],1)
        self.assertEqual(tuple(self.taker.store.db.execute('SELECT id,held,used FROM mandates ORDER BY id')),held)
        self.assertEqual({a:d.key_n for a,d in drivers.items()},keys)
        self.assertTrue(all(not ledger.records and not ledger.transactions for ledger in ledgers.values()))


if __name__=='__main__':unittest.main()
