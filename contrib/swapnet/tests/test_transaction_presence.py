"""Active UTXO presence must not be confused with wallet history.
Run with unittest or pytest; no daemon required. Native rollback evidence is separate.
"""
import unittest
from swapnet.drivers import UTXODriver
from swapnet.errors import SwapError

TXID='ab'*32

class TransactionPresenceTests(unittest.TestCase):
    def driver(self,*,entry=None,entry_error='CHAIN_RPC',tx=None,confirmations=1,header_error=None):
        driver=UTXODriver.__new__(UTXODriver)
        driver._read_tx=lambda txid: tx or {'txid':txid}
        def rpc(method,*args):
            if method=='getmempoolentry':
                if entry_error:raise SwapError(entry_error,'Transaction not in mempool' if entry_error=='CHAIN_RPC' else 'Unavailable')
                return entry
            if method=='getblockheader':
                if header_error:raise SwapError(header_error,'Unavailable')
                return {'confirmations':confirmations}
            raise AssertionError(method)
        driver.rpc=rpc
        return driver

    def test_wallet_history_without_block_is_not_active(self):
        d=self.driver(tx={'txid':TXID,'confirmations':0})
        self.assertFalse(d.has_transaction(TXID))
        self.assertEqual(d._read_tx(TXID)['txid'],TXID)

    def test_orphan_block_is_not_active(self):
        self.assertFalse(self.driver(tx={'txid':TXID,'blockhash':'old','confirmations':6},confirmations=-1).has_transaction(TXID))

    def test_confirmed_active_block_is_present(self):
        self.assertTrue(self.driver(tx={'txid':TXID,'blockhash':'active'},confirmations=2).has_transaction(TXID))

    def test_mempool_entry_is_present(self):
        d=self.driver(entry={'vsize':131},entry_error=None)
        d._read_tx=lambda _:self.fail('Mempool presence does not need wallet history')
        self.assertTrue(d.has_transaction(TXID))

    def test_unknown_transaction_is_absent(self):
        def missing(_):raise SwapError('CHAIN_RPC','No such transaction')
        d=self.driver();d._read_tx=missing
        self.assertFalse(d.has_transaction(TXID))

    def test_rpc_failures_are_not_presence_results(self):
        for code in ['RPC_UNAVAILABLE','RPC_COOKIE','RPC_RESPONSE_ID']:
            with self.subTest(code=code),self.assertRaises(SwapError):
                self.driver(entry_error=code).has_transaction(TXID)
        with self.assertRaises(SwapError):
            self.driver(tx={'txid':TXID,'blockhash':'active'},header_error='RPC_UNAVAILABLE').has_transaction(TXID)

    def test_malformed_mempool_response_is_rejected(self):
        for entry in [None,[],{},True]:
            with self.subTest(entry=entry),self.assertRaises(SwapError):
                self.driver(entry=entry,entry_error=None).has_transaction(TXID)

    def test_read_failure_is_not_treated_as_missing(self):
        d=self.driver()
        def unavailable(_):raise SwapError('RPC_UNAVAILABLE','No reply')
        d._read_tx=unavailable
        with self.assertRaises(SwapError):d.has_transaction(TXID)

    def test_offline_refund_shortcut_keeps_output_safety_checks(self):
        from types import SimpleNamespace as NS
        from swapnet.coordinator import Coordinator
        from swapnet.machine import LegObservation
        from swapnet.policy import ChainClock, SafetyPolicy
        from swapnet.assets import Asset
        for active,coin_present,expected in [(True,False,True),(False,False,False),(False,True,True)]:
            with self.subTest(active=active,coin_present=coin_present):
                d=self.driver(entry={'vsize':131},entry_error=None) if active else self.driver()
                d.asset=Asset.parse('btx:'+'11'*32+':0:native')
                base_rpc=d.rpc
                def rpc(method,*args):
                    if method=='gettxout':return {'bestblock':'tip','scriptPubKey':{'hex':'approved'}} if coin_present else None
                    if method=='getbestblockhash':return 'tip'
                    return base_rpc(method,*args)
                d.rpc=rpc
                ref={'txid':'cd'*32,'vout':0};sent=[]
                own=NS(asset=d.asset.id,lock_domain='height',lock_value=105,lock_commitment='approved')
                agr=NS(long_leg=own,short_leg=NS(asset='btc:'+'22'*32+':0:native'))
                state={'role':'initiator','secret_exposed':False,'refs':{'a':ref},'funding_prepared':True,'funding_broadcast':True,'recovery_ready':True,'refund_op':'op','stage':'refund_broadcast'}
                op={'id':'op','kind':'refund','asset':own.asset,'metadata':{'reference':ref},'txid':TXID}
                journal=NS(operations=lambda *a,**kw:[op],broadcast=lambda *a:sent.append(a))
                c=NS(now=lambda:1000,policy=SafetyPolicy(),journal=journal,_save=lambda *a:None)
                report=NS(clock=ChainClock('btx',105,1000,1000,90,90),observation=LegObservation(True,True,True,20,False,False,False,False,1000))
                self.assertEqual(Coordinator._refund_without_bitcoin(c,'sid',state,0,agr,d,report),expected)
                self.assertEqual(len(sent),1 if not active and coin_present else 0)

if __name__=='__main__':unittest.main(verbosity=2)
